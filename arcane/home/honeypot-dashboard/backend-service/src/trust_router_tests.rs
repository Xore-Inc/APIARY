//! #3577 through the served router: the same `router(state)` main serves,
//! driven with `oneshot`, so these prove what a caller on the listener
//! sees rather than what the pure functions in trust.rs decide.
//!
//! Elasticsearch points at a closed port and no services adapter socket is
//! configured, so a request that gets past the trust middleware reaches its
//! handler and fails there (502/503) without touching anything real. The
//! tests therefore read "not 401 and not 403" as "the boundary let it in".

use crate::trust::testkit::Signer;
use crate::trust::{AssertionMode, Rotating, Trust, VerifiedActor};
use crate::{audit, config_history, es, obs, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{middleware, Extension, Router};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;

const BFF: &str = "bff-token-for-tests";
const EXPORT: &str = "export-token-for-tests";

fn audit_path(test: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("apiary-3577-{}-{test}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn state(trust: Trust, audit_file: PathBuf) -> AppState {
    AppState {
        es: Arc::new(es::Es::connect("http://127.0.0.1:9").expect("client")),
        trust: Arc::new(trust),
        audit: Arc::new(audit::AuditLogger::new(audit_file)),
        config_history: Arc::new(config_history::ConfigHistory::new(std::env::temp_dir().join("apiary-3577-history.jsonl"))),
        observability: Arc::new(obs::Obs::new(String::new())),
    }
}

fn trust(signer: &Signer, mode: AssertionMode) -> Trust {
    Trust {
        bff: Some(Rotating::new(BFF.into())),
        export: Some(Rotating::new(EXPORT.into())),
        mode,
        keys: Some(Rotating::new(signer.public())),
    }
}

async fn call(app: Router, method: &str, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app.oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn let_in(status: StatusCode) -> bool {
    status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN
}

fn now() -> i64 {
    Utc::now().timestamp()
}

const SERVICES: &str = "/api/v1/services/cowrie/restart";

// ---- the export credential -----------------------------------------------

#[tokio::test]
async fn the_export_credential_reads_the_export_and_nothing_else() {
    let signer = Signer::generate();
    for mode in [AssertionMode::Off, AssertionMode::Log, AssertionMode::Enforce] {
        let app = crate::router(state(trust(&signer, mode), audit_path("export")));
        let export = [("x-export-token", EXPORT)];
        let (status, _) = call(app.clone(), "GET", "/api/v1/ip-block-export", &export).await;
        assert!(let_in(status), "{mode:?}: export read refused with {status}");

        // A service action, also with an assertion and forged headers riding
        // along: the credential decides first and none of that is read.
        let token = signer.mint("admin", "POST", SERVICES, now());
        let (status, body) = call(app.clone(), "POST", SERVICES,
            &[("x-export-token", EXPORT), ("x-actor-assertion", &token), ("x-actor-role", "admin")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{mode:?}: {body}");

        for (method, uri) in [
            ("GET", "/api/v1/workbench/runs"),
            ("POST", "/api/v1/workbench/runs"),
            ("PUT", "/api/v1/preferences"),
            ("POST", "/api/v1/ip-block"),
            ("POST", "/api/v1/credentials"),
            ("PUT", "/api/v1/config/behavior"),
            ("GET", "/api/v1/events"),
            ("GET", "/api/v1/ip-block/192.0.2.1"),
        ] {
            let (status, _) = call(app.clone(), method, uri, &export).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{mode:?}: export credential reached {method} {uri}");
        }
        // And it is no service token: in the BFF header it is no credential.
        let (status, _) = call(app.clone(), "GET", "/api/v1/ip-block-export", &[("x-service-token", EXPORT)]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{mode:?}");
    }
}

// ---- off and log keep today's behaviour ----------------------------------

#[tokio::test]
async fn off_and_log_modes_let_the_current_dashboard_through_unchanged() {
    let signer = Signer::generate();
    for mode in [AssertionMode::Off, AssertionMode::Log] {
        let app = crate::router(state(trust(&signer, mode), audit_path("compat")));
        // What the live dashboard sends today: the token, plain actor
        // headers or query labels, and no assertion.
        let (status, body) = call(app.clone(), "POST",
            &format!("{SERVICES}?actor_subject=s&actor_username=alice"), &[("x-service-token", BFF)]).await;
        assert!(let_in(status), "{mode:?}: {status} {body}");
        let (status, body) = call(app.clone(), "GET", "/api/v1/workbench/runs",
            &[("x-service-token", BFF), ("x-actor-username", "alice"), ("x-actor-role", "admin")]).await;
        assert!(let_in(status), "{mode:?}: {status} {body}");
        // A broken assertion is reported, not acted on, in log mode.
        let (status, _) = call(app.clone(), "POST", SERVICES,
            &[("x-service-token", BFF), ("x-actor-assertion", "not.a.jws")]).await;
        assert!(let_in(status), "{mode:?}: {status}");
        let (status, _) = call(app, "POST", SERVICES, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

// ---- enforce -------------------------------------------------------------

#[tokio::test]
async fn enforce_refuses_forged_missing_expired_and_foreign_assertions() {
    let signer = Signer::generate();
    let app = crate::router(state(trust(&signer, AssertionMode::Enforce), audit_path("enforce")));
    let bff = ("x-service-token", BFF);

    let forged = [bff, ("x-actor-username", "root"), ("x-actor-role", "admin")];
    let (status, _) = call(app.clone(), "POST", SERVICES, &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "forged headers on an action");
    let (status, _) = call(app.clone(), "GET", "/api/v1/workbench/runs", &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "forged headers on an owner-scoped read");

    let (status, _) = call(app.clone(), "POST", SERVICES, &[bff]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no assertion on an action");

    let expired = signer.mint("admin", "POST", SERVICES, now() - 600);
    let (status, body) = call(app.clone(), "POST", SERVICES, &[bff, ("x-actor-assertion", &expired)]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains("expired"), "{body}");

    let foreign = Signer::generate().mint("admin", "POST", SERVICES, now());
    let (status, body) = call(app.clone(), "POST", SERVICES, &[bff, ("x-actor-assertion", &foreign)]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // A valid assertion is still worthless without the bearer credential.
    let valid = signer.mint("admin", "POST", SERVICES, now());
    let (status, _) = call(app.clone(), "POST", SERVICES, &[("x-actor-assertion", &valid)]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Plain reads keep working on the token alone.
    let (status, _) = call(app, "GET", "/api/v1/events", &[bff]).await;
    assert!(let_in(status), "{status}");
}

#[tokio::test]
async fn enforce_refuses_a_viewer_whatever_the_role_header_says() {
    let signer = Signer::generate();
    let app = crate::router(state(trust(&signer, AssertionMode::Enforce), audit_path("viewer")));
    let viewer = signer.mint("viewer", "POST", SERVICES, now());
    let (status, body) = call(app.clone(), "POST", SERVICES,
        &[("x-service-token", BFF), ("x-actor-assertion", &viewer), ("x-actor-role", "admin"), ("x-actor-username", "root")]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // The mutations the dashboard grants viewers still pass, matched by the
    // router's path template ({key}), not by the literal path.
    for (method, uri) in [("PUT", "/api/v1/preferences"), ("POST", "/api/v1/alerts/k1/ack")] {
        let viewer = signer.mint("viewer", method, uri, now());
        let (status, body) = call(app.clone(), method, uri, &[("x-service-token", BFF), ("x-actor-assertion", &viewer)]).await;
        assert!(let_in(status), "{method} {uri}: {status} {body}");
    }
}

#[tokio::test]
async fn enforce_audits_the_verified_admin_not_the_query_labels() {
    let signer = Signer::generate();
    let audit_file = audit_path("audit");
    let app = crate::router(state(trust(&signer, AssertionMode::Enforce), audit_file.clone()));
    let admin = signer.mint("admin", "POST", SERVICES, now());
    let (status, body) = call(app, "POST", &format!("{SERVICES}?actor_subject=forged&actor_username=mallory"),
        &[("x-service-token", BFF), ("x-actor-assertion", &admin)]).await;
    // Past the boundary: the handler answers that no adapter is configured.
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let line = std::fs::read_to_string(&audit_file).expect("the action was audited");
    let event: serde_json::Value = serde_json::from_str(line.lines().last().unwrap()).unwrap();
    assert_eq!(event["actor_username"], "alice", "{line}");
    assert_eq!(event["actor_subject"], "sub-alice", "{line}");
    assert!(!line.contains("mallory"), "{line}");
    let _ = std::fs::remove_file(audit_file);
}

#[tokio::test]
async fn enforce_hands_handlers_the_verified_identity_only() {
    // A probe route behind the same middleware, to read what a handler
    // receives: the rewritten headers and the extension.
    async fn probe(headers: axum::http::HeaderMap, actor: Option<Extension<VerifiedActor>>) -> String {
        format!(
            "{}|{}|{}",
            headers.get("x-actor-username").and_then(|v| v.to_str().ok()).unwrap_or("-"),
            headers.get("x-actor-role").and_then(|v| v.to_str().ok()).unwrap_or("-"),
            actor.map(|Extension(a)| a.subject).unwrap_or_else(|| "-".into()),
        )
    }
    let signer = Signer::generate();
    let state = state(trust(&signer, AssertionMode::Enforce), audit_path("probe"));
    let app = Router::new()
        .route("/api/v1/probe", post(probe).get(probe))
        .layer(middleware::from_fn_with_state(state.clone(), crate::require_service_token))
        .with_state(state);

    let admin = signer.mint("admin", "POST", "/api/v1/probe", now());
    let (status, body) = call(app.clone(), "POST", "/api/v1/probe",
        &[("x-service-token", BFF), ("x-actor-assertion", &admin), ("x-actor-username", "root"), ("x-actor-role", "viewer")]).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "alice|admin|sub-alice"));

    // A viewer on an admin mutation never reaches the handler.
    let viewer = signer.mint("viewer", "POST", "/api/v1/probe", now());
    let (status, _) = call(app.clone(), "POST", "/api/v1/probe", &[("x-service-token", BFF), ("x-actor-assertion", &viewer)]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An anonymous read reaches it with no identity at all.
    let (status, body) = call(app, "GET", "/api/v1/probe", &[("x-service-token", BFF)]).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "-|-|-"));
}

// ---- rotation ------------------------------------------------------------

#[tokio::test]
async fn a_rotated_out_token_works_during_the_overlap_and_fails_after() {
    let signer = Signer::generate();
    let rotated = |until: DateTime<Utc>| Trust {
        bff: Some(Rotating { current: "new-token".into(), previous: Some((BFF.into(), until)) }),
        ..trust(&signer, AssertionMode::Off)
    };
    let open = crate::router(state(rotated(Utc::now() + chrono::Duration::minutes(5)), audit_path("rot1")));
    let closed = crate::router(state(rotated(Utc::now() - chrono::Duration::seconds(1)), audit_path("rot2")));
    for (app, previous_ok) in [(open, true), (closed, false)] {
        let (status, _) = call(app.clone(), "GET", "/api/v1/events", &[("x-service-token", BFF)]).await;
        assert_eq!(let_in(status), previous_ok, "previous token: {status}");
        let (status, _) = call(app, "GET", "/api/v1/events", &[("x-service-token", "new-token")]).await;
        assert!(let_in(status), "current token: {status}");
    }
}

// ---- what stays public ---------------------------------------------------

#[tokio::test]
async fn probes_and_metrics_stay_public_under_enforce() {
    let signer = Signer::generate();
    let app = crate::router(state(trust(&signer, AssertionMode::Enforce), audit_path("public")));
    for uri in ["/healthz", "/livez", "/metrics"] {
        let (status, _) = call(app.clone(), "GET", uri, &[]).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
    }
    // /readyz answers without a credential too; 503 here only because the
    // test's Elasticsearch is a closed port.
    let (status, _) = call(app, "GET", "/readyz", &[]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

// ---- actors named in bodies and queries (#3577) ---------------------------
//
// Here the request has to get past the handler's own store reads, so the
// handlers talk to a loopback stand-in for Elasticsearch (and, where a route
// needs one, the honeyfs implant and the canarytokens platform) that records
// every request. What a handler wrote is then read back off that record or
// off the audit file. The client always names "bob"; the assertion is always
// alice's (trust::testkit::Signer::mint).

#[derive(Clone, Default)]
struct Upstream {
    url: String,
    seen: Arc<std::sync::Mutex<Vec<(String, String, serde_json::Value)>>>,
}

impl Upstream {
    async fn start() -> Self {
        let mut upstream = Upstream::default();
        let seen = upstream.seen.clone();
        let app = Router::new().fallback(move |method: axum::http::Method, uri: axum::http::Uri, body: String| {
            let seen = seen.clone();
            async move {
                let path = uri.path().to_string();
                let parsed = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                seen.lock().unwrap().push((method.to_string(), path.clone(), parsed));
                let (status, answer) = upstream_answer(method.as_str(), &path);
                (
                    status,
                    [("content-type", "application/json"), ("x-elastic-product", "Elasticsearch")],
                    answer.to_string(),
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
        upstream.url = format!("http://{}", listener.local_addr().expect("upstream addr"));
        tokio::spawn(async move { axum::serve(listener, app).await.expect("upstream serves") });
        upstream
    }

    /// Bodies of the requests whose method matches and whose path starts
    /// with `prefix`, oldest first.
    fn bodies(&self, method: &str, prefix: &str) -> Vec<serde_json::Value> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, path, _)| m == method && path.starts_with(prefix))
            .map(|(_, _, body)| body.clone())
            .collect()
    }

    fn last(&self, method: &str, prefix: &str) -> serde_json::Value {
        self.bodies(method, prefix).pop().unwrap_or_else(|| {
            let seen: Vec<String> = self.seen.lock().unwrap().iter().map(|(m, p, _)| format!("{m} {p}")).collect();
            panic!("no {method} {prefix}* reached the upstream; it saw {seen:?}")
        })
    }
}

/// Two operators with distinguishable preferences.
fn users_doc() -> serde_json::Value {
    let user = |subject: &str, username: &str, theme: &str| {
        serde_json::json!({
            "subject": subject, "last_username": username, "role_snapshot": "viewer",
            "preferences_revision": 0, "preferences": {"theme": theme, "rows_per_page": 25},
        })
    };
    serde_json::json!({"schema_version": 4, "revision": 1, "payload": {"users": [
        user("sub-alice", "alice", "light"), user("sub-bob", "bob", "system"),
    ]}})
}

fn upstream_answer(method: &str, path: &str) -> (StatusCode, serde_json::Value) {
    use serde_json::json;
    let doc = |source: serde_json::Value| json!({"found": true, "_seq_no": 1, "_primary_term": 1, "_source": source});
    match (method, path) {
        ("GET", "/dashboard-users-v1/_doc/users") => (StatusCode::OK, doc(users_doc())),
        ("GET", "/dashboard-config-v1/_doc/config") => (
            StatusCode::OK,
            doc(json!({"schema_version": 4, "revision": 1, "payload": {"behavior": {"show_problem_report_button": true}}})),
        ),
        ("GET", "/dashboard-credentials-v1/_doc/cred-1") => (
            StatusCode::OK,
            doc(json!({"id": "cred-1", "path": "home/root/.creds", "username": "svc", "password": "old", "memo": "m"})),
        ),
        ("POST", "/implant") => (StatusCode::OK, json!({"ok": true, "path": "home/root/.creds", "bytes_written": 1})),
        ("POST", p) if p.ends_with("/generate") => (
            StatusCode::OK,
            json!({"token": "tok-1", "auth_token": "auth-1", "hostname": "t1.canary.apiary.test", "token_url": "http://t1.canary.apiary.test/x"}),
        ),
        (_, "/ml-anomalies/_search") => (StatusCode::OK, json!({"hits": {"total": {"value": 1}, "hits": [{"_id": "anomaly-1"}]}})),
        (_, p) if p.ends_with("/_search") => (StatusCode::OK, json!({"hits": {"total": {"value": 0}, "hits": []}})),
        ("GET", _) => (StatusCode::NOT_FOUND, json!({"found": false})),
        _ => (StatusCode::OK, json!({"result": "created", "_seq_no": 2, "_primary_term": 1})),
    }
}

struct Bound {
    app: Router,
    signer: Signer,
    audit: PathBuf,
    upstream: Upstream,
}

async fn bound(mode: AssertionMode, test: &str) -> Bound {
    let signer = Signer::generate();
    let upstream = Upstream::start().await;
    let audit = audit_path(&format!("{test}-{}", mode.as_str()));
    let history = audit_path(&format!("{test}-{}-history", mode.as_str()));
    let state = AppState {
        es: Arc::new(es::Es::connect(&upstream.url).expect("client")),
        trust: Arc::new(trust(&signer, mode)),
        audit: Arc::new(audit::AuditLogger::new(audit.clone())),
        config_history: Arc::new(config_history::ConfigHistory::new(history)),
        observability: Arc::new(obs::Obs::new(String::new())),
    };
    Bound { app: crate::router(state), signer, audit, upstream }
}

impl Bound {
    /// One BFF call as the signing dashboard makes it: the token, plus
    /// alice's assertion in `role` for this method and path (no query).
    async fn send(&self, role: Option<&str>, method: &str, uri: &str, body: Option<serde_json::Value>) -> (StatusCode, String) {
        let mut request = Request::builder().method(method).uri(uri).header("x-service-token", BFF);
        if let Some(role) = role {
            let path = uri.split('?').next().unwrap();
            request = request.header("x-actor-assertion", self.signer.mint(role, method, path, now()));
        }
        let body = match body {
            Some(json) => {
                request = request.header("content-type", "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let response = self.app.clone().oneshot(request.body(body).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The last audit entry for `action`.
    fn audited(&self, action: &str) -> serde_json::Value {
        let text = std::fs::read_to_string(&self.audit).unwrap_or_default();
        text.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .rfind(|event| event["action"] == action)
            .unwrap_or_else(|| panic!("no {action} audit entry in {text}"))
    }
}

/// Who a handler should have recorded: the client's "bob" in `off` and
/// `log` (unchanged behaviour), the asserted alice under `enforce`.
fn expected(mode: AssertionMode) -> (&'static str, &'static str) {
    if mode == AssertionMode::Enforce { ("sub-alice", "alice") } else { ("sub-bob", "bob") }
}

#[tokio::test]
async fn audited_actor_fields_are_the_verified_admin_under_enforce_only() {
    use serde_json::json;
    for mode in [AssertionMode::Off, AssertionMode::Log, AssertionMode::Enforce] {
        let b = bound(mode, "audited").await;
        let (subject, username) = expected(mode);
        let bob = "actor_subject=sub-bob&actor_username=bob";
        let bob_body = |mut body: serde_json::Value| {
            body["actor_subject"] = json!("sub-bob");
            body["actor_username"] = json!("bob");
            body
        };
        let calls: [(&str, String, Option<serde_json::Value>, &str); 5] = [
            ("PUT", format!("/api/v1/config/behavior?{bob}"), Some(json!({"default_time_window": "24h"})), "config.update"),
            // The PUT above made revision 2 (the stand-in's document is at 1).
            ("POST", "/api/v1/config/rollback".into(), Some(bob_body(json!({"revision": 2}))), "config.rollback"),
            ("POST", "/api/v1/credentials/cred-1/link-token".into(), Some(bob_body(json!({"token_id": ""}))), "credentials.unlink-token"),
            ("POST", "/api/v1/github-analysis/submit".into(), Some(bob_body(json!({"hash": "a".repeat(64)}))), "github_analysis.submit"),
            ("POST", format!("{SERVICES}?{bob}"), None, "services.restart"),
        ];
        for (method, uri, body, action) in calls {
            let (status, text) = b.send(Some("admin"), method, &uri, body).await;
            assert!(let_in(status), "{mode:?} {method} {uri}: {status} {text}");
            let event = b.audited(action);
            assert_eq!((event["actor_subject"].as_str(), event["actor_username"].as_str()), (Some(subject), Some(username)),
                "{mode:?} {method} {uri}: {event}");
        }
    }
}

#[tokio::test]
async fn stamped_attribution_is_the_verified_operator_under_enforce_only() {
    use serde_json::json;
    for mode in [AssertionMode::Off, AssertionMode::Log, AssertionMode::Enforce] {
        let b = bound(mode, "stamped").await;
        let (subject, username) = expected(mode);

        let (status, text) = b.send(Some("admin"), "POST", "/api/v1/ml-anomalies/ack", Some(json!({"key": "anomaly-1", "ack": true, "actor": "bob"}))).await;
        assert!(let_in(status), "{mode:?}: {status} {text}");
        assert_eq!(b.upstream.last("POST", "/dashboard-ml-anomaly-ack-v1/_doc/anomaly-1")["AckedBy"], username, "{mode:?} ack");

        b.upstream.seen.lock().unwrap().clear();
        let (status, text) = b.send(Some("admin"), "POST", "/api/v1/ml-anomalies/ack-all", Some(json!({"actor": "bob"}))).await;
        assert!(let_in(status), "{mode:?}: {status} {text}");
        assert_eq!(b.upstream.last("POST", "/dashboard-ml-anomaly-ack-v1/_doc/anomaly-1")["AckedBy"], username, "{mode:?} ack-all");

        let (status, text) = b.send(Some("admin"), "POST", "/api/v1/ml-anomalies/disposition",
            Some(json!({"key": "anomaly-1", "status": "false_positive", "actor": "bob"}))).await;
        assert!(let_in(status), "{mode:?}: {status} {text}");
        assert_eq!(b.upstream.last("POST", "/ml-anomalies/_update/anomaly-1")["doc"]["disposition_by"], username, "{mode:?} disposition");

        let (status, text) = b.send(Some("admin"), "POST", "/api/v1/ip-block", Some(json!({"ip": "192.0.2.9", "blocked": true, "actor": "bob"}))).await;
        assert!(let_in(status), "{mode:?}: {status} {text}");
        assert_eq!(b.upstream.last("POST", "/dashboard-ip-block-v1/_doc/192.0.2.9")["BlockedBy"], username, "{mode:?} ip-block");

        // A viewer may file a problem report; the display name the client
        // supplied cannot be verified, so enforce drops it and the record
        // falls back to the asserted username.
        let (status, text) = b.send(Some("viewer"), "POST",
            "/api/v1/problem-reports?actor_subject=sub-bob&actor_username=bob&actor_display_name=Bob",
            Some(json!({"expected": "it works"}))).await;
        assert!(let_in(status), "{mode:?}: {status} {text}");
        let report = b.upstream.last("POST", "/dashboard-problem-reports-v1/");
        let name = if mode == AssertionMode::Enforce { "alice" } else { "Bob" };
        assert_eq!((report["submitted_by"].as_str(), report["submitted_by_name"].as_str()), (Some(subject), Some(name)), "{mode:?}: {report}");
    }
}

#[tokio::test]
async fn enforce_binds_preferences_to_the_verified_operator() {
    use serde_json::json;
    for mode in [AssertionMode::Off, AssertionMode::Log, AssertionMode::Enforce] {
        // A viewer naming bob, and an admin doing the same: nothing in the
        // dashboard edits another operator's preferences, so admin is bound
        // too.
        for role in ["viewer", "admin"] {
            let b = bound(mode, &format!("prefs-{role}")).await;
            let (subject, username) = expected(mode);
            let mine = |doc: &serde_json::Value, who: &str| {
                doc["payload"]["users"].as_array().unwrap().iter().find(|u| u["subject"] == who).cloned().unwrap()
            };

            let (status, text) = b.send(Some(role), "PUT", "/api/v1/preferences",
                Some(json!({"subject": "sub-bob", "username": "bob", "patch": {"theme": "dark"}}))).await;
            assert_eq!(status, StatusCode::OK, "{mode:?} {role}: {text}");
            let written = b.upstream.last("POST", "/dashboard-users-v1/_doc/users");
            let other = if subject == "sub-alice" { "sub-bob" } else { "sub-alice" };
            let untouched = if other == "sub-alice" { "light" } else { "system" };
            assert_eq!(mine(&written, subject)["preferences"]["theme"], "dark", "{mode:?} {role}: {written}");
            assert_eq!(mine(&written, other)["preferences"]["theme"], untouched, "{mode:?} {role}: {written}");
            let event = b.audited("preferences.update");
            assert_eq!((event["actor_subject"].as_str(), event["actor_username"].as_str()), (Some(subject), Some(username)));

            let (status, text) = b.send(Some(role), "POST", "/api/v1/preferences/reset",
                Some(json!({"subject": "sub-bob", "username": "bob"}))).await;
            assert_eq!(status, StatusCode::OK, "{mode:?} {role}: {text}");
            let written = b.upstream.last("POST", "/dashboard-users-v1/_doc/users");
            assert_eq!(mine(&written, subject)["preferences_revision"], 1, "{mode:?} {role}: reset hit the wrong operator: {written}");
            assert_eq!(mine(&written, other)["preferences_revision"], 0, "{mode:?} {role}: {written}");

            // A read is bound the same way: naming bob reads alice's own
            // preferences under enforce, bob's otherwise.
            let (status, text) = b.send(Some(role), "GET", "/api/v1/preferences?subject=sub-bob&username=bob&role=admin", None).await;
            assert_eq!(status, StatusCode::OK, "{mode:?} {role}: {text}");
            let theme = if mode == AssertionMode::Enforce { "light" } else { "system" };
            assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["preferences"]["theme"], theme, "{mode:?} {role}: {text}");
        }
    }
}

#[tokio::test]
async fn enforce_refuses_an_actor_field_with_no_assertion_behind_it() {
    for mode in [AssertionMode::Off, AssertionMode::Log, AssertionMode::Enforce] {
        let b = bound(mode, "anon").await;
        // A plain read on the token alone passes the middleware under
        // enforce; naming an operator in its query is what it may not do.
        let (status, text) = b.send(None, "GET", "/api/v1/preferences?subject=sub-bob&role=admin", None).await;
        if mode == AssertionMode::Enforce {
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
            assert!(text.contains("subject names an actor"), "{text}");
        } else {
            assert_eq!(status, StatusCode::OK, "{mode:?}: {text}");
        }
    }
}

#[tokio::test]
async fn enforce_refuses_a_viewer_naming_anyone_on_an_admin_route() {
    use serde_json::json;
    let b = bound(AssertionMode::Enforce, "viewer-admin").await;
    let bob = json!({"actor_subject": "sub-bob", "actor_username": "bob", "actor": "bob"});
    let with = |extra: serde_json::Value| {
        let mut body = bob.clone();
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        body
    };
    let calls = [
        ("PUT", "/api/v1/config/behavior?actor_subject=sub-bob&actor_username=bob", Some(json!({}))),
        ("POST", "/api/v1/config/rollback", Some(with(json!({"revision": 1})))),
        ("POST", "/api/v1/credentials/cred-1/link-token", Some(with(json!({"token_id": ""})))),
        ("POST", "/api/v1/credentials/cred-1/rotate", Some(bob.clone())),
        ("POST", "/api/v1/credentials", Some(bob.clone())),
        ("POST", "/api/v1/ml-anomalies/ack", Some(with(json!({"key": "anomaly-1", "ack": true})))),
        ("POST", "/api/v1/ml-anomalies/ack-all", Some(bob.clone())),
        ("POST", "/api/v1/ml-anomalies/disposition", Some(with(json!({"key": "anomaly-1", "status": "true_positive"})))),
        ("POST", "/api/v1/ip-block", Some(with(json!({"ip": "192.0.2.9", "blocked": true})))),
        ("POST", "/api/v1/github-analysis/submit", Some(with(json!({"hash": "a".repeat(64)})))),
    ];
    for (method, uri, body) in calls {
        let (status, text) = b.send(Some("viewer"), method, uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {text}");
    }
    assert!(b.upstream.bodies("PUT", "/").is_empty() && b.upstream.bodies("POST", "/").is_empty(), "a refused request reached the store");
}

/// The three routes that need an external service configured by
/// environment: the honeyfs implant (credential create/rotate) and the
/// canarytokens platform. Only this test sets those variables.
#[tokio::test]
async fn attribution_on_routes_with_external_dependencies() {
    use serde_json::json;
    for mode in [AssertionMode::Off, AssertionMode::Enforce] {
        let b = bound(mode, "external").await;
        std::env::set_var("HONEYFS_IMPLANT_URL", &b.upstream.url);
        std::env::set_var("CANARYTOKENS_API_URL", &b.upstream.url);
        std::env::set_var("CANARYTOKENS_ADAPTER_WEBHOOK_URL", "http://adapter.apiary.test/hook");
        let (subject, username) = expected(mode);
        let bob = |mut body: serde_json::Value| {
            body["actor_subject"] = json!("sub-bob");
            body["actor_username"] = json!("bob");
            body
        };

        let (status, text) = b.send(Some("admin"), "POST", "/api/v1/credentials",
            Some(bob(json!({"path": "home/root/.creds", "username": "svc", "password": "p", "memo": "m"})))).await;
        assert_eq!(status, StatusCode::OK, "{mode:?}: {text}");
        let event = b.audited("credentials.create");
        assert_eq!((event["actor_subject"].as_str(), event["actor_username"].as_str()), (Some(subject), Some(username)));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["created_by"], username, "{mode:?}");

        let (status, text) = b.send(Some("admin"), "POST", "/api/v1/credentials/cred-1/rotate", Some(bob(json!({})))).await;
        assert_eq!(status, StatusCode::OK, "{mode:?}: {text}");
        let event = b.audited("credentials.rotate");
        assert_eq!((event["actor_subject"].as_str(), event["actor_username"].as_str()), (Some(subject), Some(username)));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["rotated_by"], username, "{mode:?}");

        // Canarytoken creation is a viewer mutation; `created_by` was the
        // client's display name until #3577.
        let (status, text) = b.send(Some("viewer"), "POST", "/api/v1/canarytokens",
            Some(json!({"token_type": "adobe_pdf", "memo": "m", "created_by": "Bob Display"}))).await;
        assert_eq!(status, StatusCode::OK, "{mode:?}: {text}");
        let created = if mode == AssertionMode::Enforce { "alice" } else { "Bob Display" };
        assert_eq!(b.upstream.last("POST", "/dashboard-canarytokens-v1/_doc/tok-1")["created_by"], created, "{mode:?}");
    }
}
