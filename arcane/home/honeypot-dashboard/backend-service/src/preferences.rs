//! Per-user preference sync (#1612), ported from settings_users.go /
//! settings_api.go: one subject's preferences live nested in the shared
//! dashboard-users-v1/users document, alongside the read-only operator
//! roster config.rs's `users` handler already serves. Identity travels as
//! plain request params supplied by the BFF (subject/username/role) —
//! the same trust model ip_block.rs's `actor` body field already uses —
//! rather than a new header-based scheme.
//!
//! #3577: those params go through `trust::ActorBinding`. Under
//! `ACTOR_ASSERTION_MODE=enforce` they are the verified actor's, whatever
//! the client sent, so an operator reads and writes only their own
//! preferences (an admin included: nothing in the dashboard edits another
//! operator's). `off` takes them as sent, as before; `log` reports a
//! mismatch.
//!
//! Deliberately simpler than the Go tier: no per-subject ETag/If-Match
//! compare-and-swap (nothing else in this crate has that yet either) and
//! GET never refreshes an already-projected subject's last_seen_at/role —
//! only first contact writes, so a preference *read* never costs an ES
//! write. Follow-up if that's needed: throttled last_seen refresh like
//! userStore.Upsert's 5-minute window.

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditEvent;
use crate::trust::{ActorBinding, ActorField};
use crate::AppState;

const USERS_INDEX: &str = "dashboard-users-v1";
const USERS_ID: &str = "users";
const SCHEMA_VERSION: u64 = 4;

async fn load_users_doc(state: &AppState) -> anyhow::Result<Value> {
    if let Some(doc) = state.es.get_doc(USERS_INDEX, USERS_ID).await? {
        return Ok(doc);
    }
    let result = state
        .es
        .search_index(
            &[USERS_INDEX],
            json!({"size": 1, "sort": [{"revision": {"order": "desc", "unmapped_type": "long"}}]}),
        )
        .await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .unwrap_or_else(|| json!({"schema_version": SCHEMA_VERSION, "revision": 0, "payload": {"users": []}})))
}

async fn save_users_doc(state: &AppState, mut doc: Value) -> anyhow::Result<Value> {
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    if doc["schema_version"].is_null() {
        doc["schema_version"] = json!(SCHEMA_VERSION);
    }
    state.es.index_doc(USERS_INDEX, USERS_ID, doc.clone()).await?;
    Ok(doc)
}

fn users_array(doc: &mut Value) -> &mut Vec<Value> {
    if !doc["payload"]["users"].is_array() {
        doc["payload"]["users"] = json!([]);
    }
    doc["payload"]["users"].as_array_mut().unwrap()
}

fn find_user<'a>(doc: &'a mut Value, subject: &str) -> Option<&'a mut Value> {
    users_array(doc).iter_mut().find(|u| u["subject"].as_str() == Some(subject))
}

fn default_preferences(timezone: &str) -> Value {
    let tz = if timezone.trim().is_empty() { "browser" } else { timezone.trim() };
    json!({
        "theme": "system",
        "palette": "claude",
        "density": "comfortable",
        "reduced_motion": "system",
        "collapsed_sidebar": false,
        "landing_page": "/",
        "remember_filters": false,
        "rows_per_page": 50,
        "wrap_long_values": false,
        "timezone": tz,
        "clock": "h24",
        "timestamps": "relative",
        "auto_refresh": true,
        "refresh_interval_seconds": 30,
        "live_toasts": true,
        "live_toast_interval_seconds": 60,
        "map_basemap": "osm",
        "map_clustering": true,
        "map_animation": true,
        "high_contrast": false,
        "large_evidence_text": false,
        "notify_severity": "high",
        "notify_sound": false,
        "notify_desktop": false,
        "default_event_window": "24h",
        "preserve_filters": false,
        "open_details_new_tab": false,
    })
}

fn new_projection(subject: &str, username: &str, role: &str, timezone: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "subject": subject,
        "last_username": username,
        "role_snapshot": role,
        "first_seen_at": now,
        "last_seen_at": now,
        "preferences_version": SCHEMA_VERSION,
        "preferences_revision": 0,
        "preferences": default_preferences(timezone),
    })
}

#[derive(Deserialize)]
pub struct PreferencesQuery {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    timezone: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/preferences",
    summary = "One user's saved preferences.",
    params(
        ("subject" = inline(Option<String>), Query, description = "OIDC subject. Required -- an empty value is a 400."),
        ("username" = inline(Option<String>), Query, description = "Operator name."),
        ("role" = inline(Option<String>), Query, description = "Operator role."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn get(
    State(state): State<AppState>,
    binding: ActorBinding,
    axum::extract::Query(query): axum::extract::Query<PreferencesQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let query = PreferencesQuery {
        subject: binding.bind("subject", ActorField::Subject, &query.subject)?,
        username: binding.bind("username", ActorField::Username, &query.username)?,
        role: binding.bind("role", ActorField::Role, &query.role)?,
        timezone: query.timezone,
    };
    if query.subject.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "subject is required".into()));
    }
    let mut doc = load_users_doc(&state).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if let Some(user) = find_user(&mut doc, &query.subject) {
        let preferences = user["preferences"].clone();
        let revision = user["preferences_revision"].as_i64().unwrap_or(0);
        return Ok(Json(json!({"preferences": preferences, "revision": revision})));
    }
    let projection = new_projection(&query.subject, &query.username, &query.role, &query.timezone);
    let preferences = projection["preferences"].clone();
    users_array(&mut doc).push(projection);
    save_users_doc(&state, doc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(json!({"preferences": preferences, "revision": 0})))
}

/// The fields settings_api.go's preferencesPatch allows. `palette` rides
/// along since Go commit 31286e1 (#1621) added it there — before that,
/// every appearance save carrying it 400'd on the strict decoder.
#[derive(Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
struct PreferencesPatch {
    theme: Option<String>,
    palette: Option<String>,
    density: Option<String>,
    reduced_motion: Option<String>,
    collapsed_sidebar: Option<bool>,
    landing_page: Option<String>,
    remember_filters: Option<bool>,
    rows_per_page: Option<i64>,
    wrap_long_values: Option<bool>,
    timezone: Option<String>,
    clock: Option<String>,
    timestamps: Option<String>,
    auto_refresh: Option<bool>,
    refresh_interval_seconds: Option<i64>,
    live_toasts: Option<bool>,
    live_toast_interval_seconds: Option<i64>,
    map_basemap: Option<String>,
    map_clustering: Option<bool>,
    map_animation: Option<bool>,
    high_contrast: Option<bool>,
    large_evidence_text: Option<bool>,
    notify_severity: Option<String>,
    notify_sound: Option<bool>,
    notify_desktop: Option<bool>,
    default_event_window: Option<String>,
    preserve_filters: Option<bool>,
    open_details_new_tab: Option<bool>,
}

/// Preference values the server owns outright. These mirror the option sets
/// the settings page renders and, where one already existed, the set
/// `config.rs` validates for the deployment-wide default -- `default_time_window`,
/// `rows_per_page_options`, `refresh_interval_seconds_options` and
/// `map_provider` are the same lists, deliberately, because two lists drift.
const THEME_MODES: &[&str] = &["system", "dark", "light"];
const DENSITIES: &[&str] = &["comfortable", "compact"];
const MOTION: &[&str] = &["system", "on", "off"];
const CLOCKS: &[&str] = &["h24", "h12"];
const TIMESTAMPS: &[&str] = &["relative", "absolute"];
const BASEMAPS: &[&str] = &["osm"];
const SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];
const EVENT_WINDOWS: &[&str] = &["1h", "6h", "24h", "7d", "30d"];
const ROWS_PER_PAGE: &[i64] = &[10, 25, 50, 100];
const REFRESH_SECONDS: &[i64] = &[10, 15, 30, 60, 120, 300];
/// Matches TOAST_INTERVALS in settings.tsx. 3 is "every new batch"; the rest
/// are the coarser choices an operator picks when the stream is busy.
/// How often the shell polls for operational problems (#1900).
///
/// These were batching cadences for the old "N new events" toast, which is
/// why 3 was in the list at all. That toast is gone -- the shell now
/// reports stale sensors, stalled ingestion and cluster trouble -- and none
/// of those move faster than minutes, so a 3-second poll would be twenty
/// requests a minute for a figure that has not changed.
///
/// 3 and 30 stay accepted rather than rejected. A preference saved before
/// this change is still on an account somewhere, and refusing it would turn
/// an old setting into a validation error on an unrelated save. LiveToasts
/// clamps to a one-minute floor, so an old value is honoured as "as often
/// as it is worth asking" instead.
const TOAST_SECONDS: &[i64] = &[3, 30, 60, 120, 300, 900];

fn one_of(field: &str, value: &Option<String>, allowed: &[&str], problems: &mut Vec<String>) {
    if let Some(v) = value {
        if !allowed.contains(&v.as_str()) {
            problems.push(format!("{field} must be one of {}", allowed.join(", ")));
        }
    }
}

fn one_of_int(field: &str, value: &Option<i64>, allowed: &[i64], problems: &mut Vec<String>) {
    if let Some(v) = value {
        if !allowed.contains(v) {
            let list: Vec<String> = allowed.iter().map(|n| n.to_string()).collect();
            problems.push(format!("{field} must be one of {}", list.join(", ")));
        }
    }
}

/// A theme name is checked by *shape*, not against a list.
///
/// This is the one field that must stay open. #1753 ships themes as CSS in
/// the vendored stylesheet, and a new one has to be selectable the moment it
/// is vendored -- gating that on a matching backend deploy would mean the
/// name is rejected by the API while the CSS to render it is already live.
/// The frontend follows the same rule for the same reason (#1754), so an
/// unrecognised-but-well-formed name is preserved and simply matches no CSS.
///
/// Shape-checking is still validation: it is what stops `<script>` and
/// `'; DROP TABLE` from being stored and handed back to a browser. An
/// identifier cannot contain anything but lowercase letters, digits and
/// dashes, and cannot be long.
fn theme_name(field: &str, value: &Option<String>, problems: &mut Vec<String>) {
    let Some(v) = value else { return };
    let shaped = (3..=32).contains(&v.len())
        && v.starts_with(|c: char| c.is_ascii_lowercase())
        && v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !shaped {
        problems.push(format!(
            "{field} must be 3-32 characters of lowercase letters, digits or dashes, starting with a letter"
        ));
    }
}

/// A landing page is a path this dashboard will navigate to on login.
///
/// Same trap as any other stored URL: `//evil.example` is a protocol-relative
/// URL and `/\evil.example` is treated as one by browsers, so both send the
/// user off-site from a value that reads like a path. Requiring a single
/// leading slash is what makes it a path rather than a destination.
fn landing_path(field: &str, value: &Option<String>, problems: &mut Vec<String>) {
    let Some(v) = value else { return };
    let ok = v.starts_with('/')
        && !v.starts_with("//")
        && !v.starts_with("/\\")
        && v.len() <= 512
        && !v.contains(|c: char| c.is_control());
    if !ok {
        problems.push(format!(
            "{field} must be a same-site path: one leading slash, at most 512 characters"
        ));
    }
}

/// An IANA zone name, or the sentinel `browser`.
///
/// Not checked against the tz database -- that would make the accepted set
/// depend on the container's tzdata version, so the same request could
/// succeed on one host and fail on another after an unrelated base-image
/// bump. Shape and length only.
fn timezone_name(field: &str, value: &Option<String>, problems: &mut Vec<String>) {
    let Some(v) = value else { return };
    let ok = v == "browser"
        || (v.len() <= 64
            && v.starts_with(|c: char| c.is_ascii_alphabetic())
            && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+')));
    if !ok {
        problems.push(format!("{field} must be an IANA zone name such as Europe/Berlin, or browser"));
    }
}

impl PreferencesPatch {
    fn empty(&self) -> bool {
        *self == PreferencesPatch::default()
    }

    /// Every problem with the patch, or an empty vec.
    ///
    /// Returns all of them rather than the first: a settings page saves the
    /// whole form at once, and reporting one bad field per round trip makes
    /// fixing three of them a three-request conversation.
    ///
    /// Booleans are not checked -- serde already rejected anything that was
    /// not a bool before this runs.
    fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        one_of("theme", &self.theme, THEME_MODES, &mut p);
        theme_name("palette", &self.palette, &mut p);
        one_of("density", &self.density, DENSITIES, &mut p);
        one_of("reduced_motion", &self.reduced_motion, MOTION, &mut p);
        one_of("clock", &self.clock, CLOCKS, &mut p);
        one_of("timestamps", &self.timestamps, TIMESTAMPS, &mut p);
        one_of("map_basemap", &self.map_basemap, BASEMAPS, &mut p);
        one_of("notify_severity", &self.notify_severity, SEVERITIES, &mut p);
        one_of("default_event_window", &self.default_event_window, EVENT_WINDOWS, &mut p);
        one_of_int("rows_per_page", &self.rows_per_page, ROWS_PER_PAGE, &mut p);
        one_of_int("refresh_interval_seconds", &self.refresh_interval_seconds, REFRESH_SECONDS, &mut p);
        one_of_int(
            "live_toast_interval_seconds",
            &self.live_toast_interval_seconds,
            TOAST_SECONDS,
            &mut p,
        );
        landing_path("landing_page", &self.landing_page, &mut p);
        timezone_name("timezone", &self.timezone, &mut p);
        p
    }

    /// Applies every present field onto `prefs`, returning the dotted
    /// (flat, here) field names that changed for the audit record.
    fn apply(self, prefs: &mut Value) -> Vec<String> {
        let mut fields = Vec::new();
        macro_rules! set {
            ($name:literal, $field:expr) => {
                if let Some(value) = $field {
                    prefs[$name] = json!(value);
                    fields.push($name.to_string());
                }
            };
        }
        set!("theme", self.theme);
        set!("palette", self.palette);
        set!("density", self.density);
        set!("reduced_motion", self.reduced_motion);
        set!("collapsed_sidebar", self.collapsed_sidebar);
        set!("landing_page", self.landing_page);
        set!("remember_filters", self.remember_filters);
        set!("rows_per_page", self.rows_per_page);
        set!("wrap_long_values", self.wrap_long_values);
        set!("timezone", self.timezone);
        set!("clock", self.clock);
        set!("timestamps", self.timestamps);
        set!("auto_refresh", self.auto_refresh);
        set!("refresh_interval_seconds", self.refresh_interval_seconds);
        set!("live_toasts", self.live_toasts);
        set!("live_toast_interval_seconds", self.live_toast_interval_seconds);
        set!("map_basemap", self.map_basemap);
        set!("map_clustering", self.map_clustering);
        set!("map_animation", self.map_animation);
        set!("high_contrast", self.high_contrast);
        set!("large_evidence_text", self.large_evidence_text);
        set!("notify_severity", self.notify_severity);
        set!("notify_sound", self.notify_sound);
        set!("notify_desktop", self.notify_desktop);
        set!("default_event_window", self.default_event_window);
        set!("preserve_filters", self.preserve_filters);
        set!("open_details_new_tab", self.open_details_new_tab);
        fields
    }
}

#[derive(Deserialize)]
pub struct PreferencesWriteBody {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    username: String,
    // Accepted for symmetry with the GET/reset params but unused here:
    // PUT never touches role_snapshot, matching UpdatePreferences.
    #[serde(default, rename = "role")]
    _role: String,
    #[serde(default)]
    patch: PreferencesPatch,
}

#[utoipa::path(
    put,
    path = "/api/v1/preferences",
    summary = "Replace one user's saved preferences.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `PreferencesWriteBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn put(
    State(state): State<AppState>,
    binding: ActorBinding,
    Json(mut body): Json<PreferencesWriteBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    body.subject = binding.bind("subject", ActorField::Subject, &body.subject)?;
    body.username = binding.bind("username", ActorField::Username, &body.username)?;
    if body.subject.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "subject is required".into()));
    }
    if body.patch.empty() {
        return Err((StatusCode::BAD_REQUEST, "patch must set at least one preference field".into()));
    }
    // Before the document is loaded, let alone written: a rejected patch
    // should not cost a round trip to the store.
    let problems = body.patch.problems();
    if !problems.is_empty() {
        return Err((StatusCode::BAD_REQUEST, problems.join("; ")));
    }
    let mut doc = load_users_doc(&state).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let Some(user) = find_user(&mut doc, &body.subject) else {
        return Err((StatusCode::NOT_FOUND, "no settings record yet; GET /api/v1/preferences first".into()));
    };
    let fields = body.patch.apply(&mut user["preferences"]);
    let revision = user["preferences_revision"].as_i64().unwrap_or(0) + 1;
    user["preferences_revision"] = json!(revision);
    let preferences = user["preferences"].clone();
    save_users_doc(&state, doc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    state.audit.log(AuditEvent {
        actor_subject: body.subject,
        actor_username: body.username,
        action: "preferences.update".into(),
        fields,
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(json!({"preferences": preferences, "revision": revision})))
}

#[derive(Deserialize)]
pub struct PreferencesResetBody {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    username: String,
    #[serde(default, rename = "role")]
    _role: String,
    #[serde(default)]
    timezone: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/preferences/reset",
    summary = "Drop one user's saved preferences back to the defaults.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `PreferencesResetBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn reset(
    State(state): State<AppState>,
    binding: ActorBinding,
    Json(mut body): Json<PreferencesResetBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    body.subject = binding.bind("subject", ActorField::Subject, &body.subject)?;
    body.username = binding.bind("username", ActorField::Username, &body.username)?;
    if body.subject.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "subject is required".into()));
    }
    let mut doc = load_users_doc(&state).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let Some(user) = find_user(&mut doc, &body.subject) else {
        return Err((StatusCode::NOT_FOUND, "no settings record yet; GET /api/v1/preferences first".into()));
    };
    user["preferences"] = default_preferences(&body.timezone);
    let revision = user["preferences_revision"].as_i64().unwrap_or(0) + 1;
    user["preferences_revision"] = json!(revision);
    let preferences = user["preferences"].clone();
    save_users_doc(&state, doc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    state.audit.log(AuditEvent {
        actor_subject: body.subject,
        actor_username: body.username,
        action: "preferences.update".into(),
        fields: vec!["*".into()],
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(json!({"preferences": preferences, "revision": revision})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(json_text: &str) -> PreferencesPatch {
        serde_json::from_str(json_text).expect("patch should deserialize")
    }

    #[test]
    fn the_payload_from_the_issue_is_rejected() {
        // #1756 quoted this exact body as something the API accepted and
        // stored, then handed back to a browser on the next GET.
        let p = patch(
            r#"{"theme": "'; DROP TABLE", "palette": "<script>", "rows_per_page": -9007199254740991}"#,
        );
        let problems = p.problems();
        assert_eq!(problems.len(), 3, "each bad field reports once: {problems:?}");
        assert!(problems.iter().any(|m| m.starts_with("theme")));
        assert!(problems.iter().any(|m| m.starts_with("palette")));
        assert!(problems.iter().any(|m| m.starts_with("rows_per_page")));
    }

    #[test]
    fn every_default_value_validates() {
        // Whatever else changes, the values the server itself writes on
        // first contact must survive being sent back to it -- otherwise a
        // settings page that saves an untouched form fails.
        let defaults = default_preferences("Europe/Berlin");
        let p: PreferencesPatch =
            serde_json::from_value(defaults).expect("defaults should match the patch shape");
        assert!(p.problems().is_empty(), "{:?}", p.problems());
    }

    #[test]
    fn an_unknown_but_well_formed_theme_name_is_accepted() {
        // The point of the open shape check: a theme ships as CSS in the
        // vendored stylesheet and must be selectable without a backend
        // deploy. Gating on a list would reject the name while the CSS that
        // renders it is already live.
        for name in ["nightwatch", "claude", "slate", "high-contrast", "ocean2"] {
            let p = patch(&format!(r#"{{"palette": "{name}"}}"#));
            assert!(p.problems().is_empty(), "{name} should be accepted: {:?}", p.problems());
        }
    }

    #[test]
    fn theme_names_that_are_not_identifiers_are_rejected() {
        for name in [
            "<script>",         // the stored-XSS shape
            "Claude",           // uppercase: not an identifier we emit
            "ab",               // too short
            "a".repeat(33).as_str(),
            "-leading-dash",
            "has space",
            "has_underscore",
            "",
        ] {
            let p = patch(&format!(r#"{{"palette": {}}}"#, serde_json::to_string(name).unwrap()));
            assert!(!p.problems().is_empty(), "{name:?} should be rejected");
        }
    }

    #[test]
    fn landing_page_cannot_send_the_user_off_site() {
        // A stored landing page is navigated to on login, so the usual
        // path-shaped escapes matter: both of these read as paths and are
        // not.
        for bad in ["//evil.example", "/\\evil.example", "https://evil.example", "not-a-path"] {
            let p = patch(&format!(r#"{{"landing_page": {}}}"#, serde_json::to_string(bad).unwrap()));
            assert!(!p.problems().is_empty(), "{bad:?} should be rejected");
        }
        for good in ["/", "/events", "/investigate/lookup?ip=1.2.3.4"] {
            let p = patch(&format!(r#"{{"landing_page": {}}}"#, serde_json::to_string(good).unwrap()));
            assert!(p.problems().is_empty(), "{good:?} should be accepted: {:?}", p.problems());
        }
    }

    #[test]
    fn numeric_preferences_are_bounded_to_the_offered_options() {
        // The sharper edge in #1756: rows_per_page reaches a query.
        for bad in [0, -1, 10_000_000, 51] {
            let p = patch(&format!(r#"{{"rows_per_page": {bad}}}"#));
            assert!(!p.problems().is_empty(), "{bad} should be rejected");
        }
        for good in ROWS_PER_PAGE {
            let p = patch(&format!(r#"{{"rows_per_page": {good}}}"#));
            assert!(p.problems().is_empty(), "{good} should be accepted");
        }
        for bad in [0, 7, 86_400] {
            let p = patch(&format!(r#"{{"refresh_interval_seconds": {bad}}}"#));
            assert!(!p.problems().is_empty(), "{bad} should be rejected");
        }
    }

    #[test]
    fn timezone_accepts_iana_names_and_the_browser_sentinel() {
        for good in ["browser", "Europe/Berlin", "America/Argentina/Buenos_Aires", "Etc/GMT+3", "UTC"] {
            let p = patch(&format!(r#"{{"timezone": {}}}"#, serde_json::to_string(good).unwrap()));
            assert!(p.problems().is_empty(), "{good} should be accepted: {:?}", p.problems());
        }
        for bad in ["<script>", "/etc/passwd", "a".repeat(65).as_str()] {
            let p = patch(&format!(r#"{{"timezone": {}}}"#, serde_json::to_string(bad).unwrap()));
            assert!(!p.problems().is_empty(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn the_toast_interval_is_accepted_and_bounded() {
        // #1850: this field existed in the frontend and not here, and the
        // struct is deny_unknown_fields -- so saving the Time pane was
        // rejected outright, the value never stored, and the client fell back
        // to its 3-second default no matter what the operator chose. The
        // toasts then fired every 3 seconds forever.
        for good in TOAST_SECONDS {
            let p = patch(&format!(r#"{{"live_toast_interval_seconds": {good}}}"#));
            assert!(p.problems().is_empty(), "{good} should be accepted: {:?}", p.problems());
        }
        for bad in [0, 1, 7, 3600, -1] {
            let p = patch(&format!(r#"{{"live_toast_interval_seconds": {bad}}}"#));
            assert!(!p.problems().is_empty(), "{bad} should be rejected");
        }
    }

    #[test]
    fn the_whole_time_pane_saves_in_one_patch() {
        // The pane sends every one of its fields together. A single unknown
        // field among them fails the lot, which is how one missing field took
        // the other six down with it.
        let p = patch(
            r#"{"timezone": "Europe/Berlin", "clock": "h24", "timestamps": "relative",
                 "auto_refresh": true, "refresh_interval_seconds": 30,
                 "live_toasts": true, "live_toast_interval_seconds": 120}"#,
        );
        assert!(p.problems().is_empty(), "{:?}", p.problems());
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        // A settings page saves the whole form at once; one bad field per
        // round trip makes fixing three of them a three-request conversation.
        let p = patch(r#"{"theme": "nope", "density": "nope", "clock": "nope"}"#);
        assert_eq!(p.problems().len(), 3);
    }
}
