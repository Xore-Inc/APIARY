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
