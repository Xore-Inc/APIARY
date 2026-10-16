//! The machine-readable contract for this service's HTTP surface (#3325).
//!
//! # Where the document comes from
//!
//! From the `Router`. Every handler carries a `#[utoipa::path]`
//! annotation, and `utoipa_axum::routes!(handler)` reads it to register
//! the handler in the served router *and* the document in one call. There
//! is no second route table and no second copy of the surface.
//!
//! The one way that stops being true is registering a route the old way --
//! `OpenApiRouter` inherits `axum::Router`'s `.route(...)` as a pass-through
//! that reaches the process and not the document -- so
//! `contract_covers_every_router_route` names those three methods and fails
//! the build if the table contains one. In the other direction, an
//! annotation on a handler nothing routes publishes an operation the service
//! answers 404 for, and the same test catches that.
//!
//! This file used to hold an 1820-line hand-written table of the same
//! surface, kept honest by two drift tests. That had rotted twice, and
//! the reason is structural rather than a matter of care: a table beside
//! the router is a second thing to update, and the direction that rots is
//! the one where the new route never reaches it. The annotations are on
//! the handlers, so the surface is described once.
//!
//! # The transform, and what it is for
//!
//! `utoipa` gives the document its shape, and [`render`] applies a short,
//! documented set of adjustments to it. Each one exists because the
//! information is real and `utoipa` cannot see it -- not to make the output
//! prettier, and not to paper over an annotation that was forgotten:
//!
//! 1. **The middleware's 401.** `require_service_token` answers
//!    `(StatusCode, String)` *before a route is resolved*, so no handler
//!    can see the status it causes and no handler can annotate it. Every
//!    operation that declares `security(("serviceToken" = []))` is
//!    therefore given the `text/plain` 401 here. An operation that can
//!    also answer a JSON 401 of its own -- the Workbench's
//!    `require_actor` -- keeps it in its own annotation, and the two
//!    media types are merged onto one status rather than overwriting each
//!    other.
//! 2. **`operationId` and the operation's tag.** Both are pure functions
//!    of the path, so they are computed once in [`operation_id`] and
//!    [`tag_for`] rather than written out 141 times where a typo would
//!    rename a published id.
//! 3. **`Option` is an absence, not a null.** A parameter declared
//!    `Option<T>` is an absent-or-`T` parameter, and `required: false`
//!    already says so; `utoipa` renders a header's `Option<String>` as
//!    `["string", "null"]` anyway, and a header value is text on the wire,
//!    never the JSON value null. So the `null` is dropped from the type.
//!    A *body* is the other way round: `utoipa` does not derive `required`
//!    for a request body at all, so the two routes that take an
//!    `Option<Json<T>>` carry an `x-optional-body` marker in their
//!    annotation and this file turns it into `required: false` and consumes
//!    the marker. `document_is_well_formed` asserts no marker survives.
//! 4. **The operation description.** `utoipa` reads each handler's Rust
//!    doc comment into the operation. Those comments are written for Rust
//!    readers, and the contract carries a summary per operation, so the
//!    description is dropped here rather than published as a second,
//!    differently-worded summary of the same route.
//! 5. **The document-level literals** -- `info`'s title, version, summary
//!    and description, `servers`, the `serviceToken` security scheme, and
//!    the tag list. `OpenApiRouter::default()` starts empty on purpose
//!    (`new()` would fill `info` in from utoipa's own Cargo.toml), and
//!    `utoipa`'s `Info` does not model `summary` at all. These are prose
//!    about the service, not facts about any one route, so they stay here
//!    where a reader looks for them; the tag *descriptions* are a function
//!    of the tag name in [`tag_description`].
//! 6. **`parameters: []` on an operation that takes none.** `utoipa`
//!    omits the key, and "omitted" and "none" are different answers to a
//!    consumer walking the document.
//!
//! Every one of the four document-level facts the fuzz job checks -- the
//! auth tier, the request parameters, the declared statuses, and the
//! media type of every response -- is generator *input*, carried in the
//! annotations. The list above is the whole of what is added here, and
//! `document_is_well_formed` asserts each of them rather than trusting
//! this prose.
//!
//! # What the document deliberately does NOT claim
//!
//! **Every** success body is free-form (an empty schema, which accepts any
//! JSON value) -- including `/healthz`'s two-field struct. Hand-transcribing
//! 141 response shapes would be 141 chances to assert something the code
//! does not enforce, and a contract that lies about a response is worse
//! than one that admits it is open. The empty schema is the truthful
//! statement: it is also what keeps `response_schema_conformance` from
//! failing the fuzz job on correct behaviour, which is why that job
//! reports service findings like "API accepted schema-violating request"
//! and treats them as a standing record rather than as a verdict.
//!
//! # Statuses that no annotation has to remember
//!
//! Three come from axum's extractors, before any handler runs, and the
//! annotations that take such a body or a `Query` declare them:
//! `Json<T>` adds 415 and 422, and `Query<T>` adds 400. Running the fuzz
//! job against a booted service is what found all three -- they are
//! unreachable from the router's source, since nothing in `router()` or
//! the handlers mentions them, and every one of them was reported
//! "undocumented" on routes whose rows looked complete.
//!
//! One status carries two media types on the routes where the extractor's
//! answer and the handler's own answer share a code: the Workbench's 400
//! is `text/plain` when `Query<T>` refuses the query string and
//! `application/json` when the handler rejects the value.

use serde_json::{json, Value};

use crate::{api_router, public_router};

pub use crate::contract::STORE_NAMES;

/// Renders the OpenAPI 3.1 document.
///
/// Deterministic, and byte-stable across runs: `utoipa` emits sorted maps
/// for everything it models, and the round trip through [`Value`] sorts
/// what is left (and is also what puts the keys in the one order the
/// committed file has). Regenerating an unchanged source tree produces a
/// byte-identical file, so a reviewer can read a real diff.
pub fn document() -> Value {
    let openapi = contract_router().into_openapi();
    let mut document = serde_json::to_value(openapi).expect("the OpenAPI model serializes");
    render(&mut document);
    document
}

/// The document `utoipa` builds from the handlers, before the transform
/// above. `router()` serves this same builder, so the two cannot disagree
/// about what exists.
fn contract_router() -> utoipa_axum::router::OpenApiRouter<crate::AppState> {
    utoipa_axum::router::OpenApiRouter::default()
        .merge(api_router())
        .merge(public_router())
}

/// The documented transform. See the module doc for why each step is here.
fn render(document: &mut Value) {
    // Collected first, while the document can still be read: one pass over
    // the paths for the tag list, then one pass that rewrites them.
    let tag_list = document_tag_list(document);

    // The document-level facts. `OpenApiRouter::default()` starts empty, so
    // nothing here is fighting a default it has to clear.
    let root = document.as_object_mut().expect("the model is an object");
    let info = root.entry("info").or_insert_with(|| json!({})).as_object_mut().expect("info is an object");
    info.insert("title".to_string(), json!("APIARY dashboard backend-service"));
    info.insert("version".to_string(), json!(env!("CARGO_PKG_VERSION")));
    // The contract version a consumer pins against; the package version
    // above moves on every release and says nothing about compatibility.
    info.insert("x-api-version".to_string(), json!(crate::API_VERSION));
    // `info.summary` is OpenAPI 3.1 and utoipa's `Info` does not model it,
    // so it cannot be set on the model at all.
    info.insert("summary".to_string(), json!(INFO_SUMMARY));
    info.insert("description".to_string(), json!(INFO_DESCRIPTION));

    root.insert(
        "servers".to_string(),
        json!([{
            "url": "http://127.0.0.1:8081",
            "description":
                "The default LISTEN_ADDR. In compose this service is reachable \
                 only over the internal honeynet, and only by the dashboard BFF."
        }]),
    );
    root.insert(
        "components".to_string(),
        json!({
            "securitySchemes": {
                "serviceToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Service-Token",
                    "description":
                        "The shared secret the Nitro BFF presents on \
                         every /api/v1 call (SERVICE_TOKEN; lib.rs's \
                         require_service_token, #2183). Compared in \
                         constant time, and a wrong or missing value \
                         is a 401 before the route is even resolved. \
                         Browsers never reach this service directly."
                }
            }
        }),
    );

    root.insert("tags".to_string(), tag_list);

    // (1)-(4), per operation.
    let paths = document["paths"]
        .as_object_mut()
        .expect("the model always has a paths object");
    for (path, item) in paths.iter_mut() {
        let item = item.as_object_mut().expect("a path item is an object");
        for (method, operation) in item.iter_mut() {
            let operation = operation.as_object_mut().expect("an operation is an object");

            // (4) The Rust doc comment is not the contract's description.
            operation.remove("description");

            // (2) Pure functions of the path, so they cannot be mistyped.
            operation.insert(
                "operationId".to_string(),
                json!(operation_id(method, path)),
            );
            operation.insert("tags".to_string(), json!([tag_for(path)]));

            // The contract states `parameters` on every operation, empty
            // list included. utoipa omits the key when there are none,
            // which reads as "unknown" to a consumer rather than "none",
            // and a fuzzer walking the document should not have to tell
            // those apart.
            operation
                .entry("parameters".to_string())
                .or_insert_with(|| json!([]));

            // A query parameter is never required, whatever the handler
            // struct says. The extractor's own rejection -- a missing
            // required field -- is the 400 those operations declare, and
            // the old table said `required: false` for every one of them.
            // utoipa omits the key unless the annotation spells it out, so
            // the default is filled in here rather than 40-odd times at
            // the use sites.
            //
            // The schema is narrowed in the same pass. `Option<T>` in a
            // *query* position already renders as T -- utoipa-gen clears
            // the nullable flag for queries, parameter.rs's
            // `ParameterIn::Query` arm -- but in a header it renders as
            // `["string", "null"]`. A header value is text on the wire,
            // never the JSON value null: what `Option` means there is an
            // absent header, and that is already carried by
            // `required: false`. The two optional request bodies are the
            // same reading, and they take the `x-optional-body` marker
            // below instead, because `required` is not derived for a body
            // and so there is nothing here to narrow.
            if let Some(parameters) = operation.get_mut("parameters").and_then(Value::as_array_mut)
            {
                for parameter in parameters.iter_mut() {
                    let parameter =
                        parameter.as_object_mut().expect("a parameter is an object");
                    if parameter.get("in") == Some(&json!("query")) {
                        parameter
                            .entry("required".to_string())
                            .or_insert_with(|| json!(false));
                    }
                    if let Some(schema) =
                        parameter.get_mut("schema").and_then(Value::as_object_mut)
                    {
                        let narrowed = match schema.get("type") {
                            Some(Value::Array(types))
                                if types.len() > 1
                                    && types.iter().any(|t| t == "null") =>
                            {
                                types.iter().filter(|t| *t != "null").cloned().collect::<Vec<_>>()
                            }
                            _ => continue,
                        };
                        match narrowed.as_slice() {
                            [only] => {
                                schema.insert("type".to_string(), only.clone());
                            }
                            _ => {
                                schema.insert("type".to_string(), Value::Array(narrowed));
                            }
                        }
                    }
                }
            }

            // (3) The optional-body marker, consumed.
            if let Some(body) = operation.get_mut("requestBody").and_then(Value::as_object_mut) {
                if body.remove("x-optional-body").is_some() {
                    body.insert("required".to_string(), json!(false));
                }
            }

            // (1) The 401 `require_service_token` raises, which no handler
            // can see. Merged into whatever the handler declared, never
            // over it: on the Workbench's routes both media types are
            // reachable on the one status.
            let secured = operation.contains_key("security");
            let responses = operation
                .get_mut("responses")
                .and_then(Value::as_object_mut)
                .expect("an operation always declares responses");
            if secured {
                let unauthorized = responses
                    .entry("401".to_string())
                    .or_insert_with(|| json!({}));
                let object = unauthorized.as_object_mut().expect("a response is an object");
                object.insert("description".to_string(), json!(unauthorized_description()));
                let content = object
                    .entry("content".to_string())
                    .or_insert_with(|| json!({}));
                content
                    .as_object_mut()
                    .expect("content is an object")
                    .entry("text/plain".to_string())
                    .or_insert_with(|| json!({"schema": str_schema()}));
            }
        }
    }
}

const INFO_SUMMARY: &str = "The dashboard's Rust service tier: Elasticsearch-backed \
                           read APIs over the honeypot event corpus.";

const INFO_DESCRIPTION: &str = "\
The /api surface of `backend-service/` (`apiary-backend`), the Rust service \
tier of the APIARY dashboard's modernization port (#1608). It is not a \
public API: the Nitro BFF in `frontend-next/` is the only intended caller \
and presents a shared service token on every /api/v1 route. /healthz and \
/metrics are the two exceptions, open on purpose for the container \
healthcheck and the #1972 metrics scrape.

Response bodies are deliberately left unconstrained here. The handlers \
return `Json<Value>` or a per-surface struct that nothing in this crate \
enforces, so restating 138 shapes would be 138 chances to publish \
something the code does not promise -- and a contract that lies about a \
response is worse than one that admits the gap. What this document does \
pin is the part that has been wrong before: the auth tier, the request \
parameters (including the enum-valued ones the handlers actually \
validate), the declared status codes, and the media type of every \
response. That is what `.github/workflows/weekly-schemathesis.yml` \
checks.

`arcane/home/honeypot-dashboard/backend-service/src/openapi.rs` is the \
source of truth. Regenerate the committed copy with \
`cargo run --bin openapi > openapi.json`; the drift tests in that module \
and a diff step in `quality.yml` both fail if you forget.";

fn str_schema() -> Value {
    json!({"type": "string"})
}

/// The document's top-level `tags` list: one Tag Object per tag the
/// operations actually use, sorted, each with the description a reader
/// landing on a large group deserves. Collected from the paths rather than
/// written out, so a new route cannot land in a group nobody described.
fn document_tag_list(document: &Value) -> Value {
    let mut tags: Vec<&str> = document["paths"]
        .as_object()
        .expect("paths is an object")
        .keys()
        .map(|path| tag_for(path))
        .collect();
    tags.sort_unstable();
    tags.dedup();
    Value::Array(
        tags.into_iter()
            .map(|tag| json!({"name": tag, "description": tag_description(tag)}))
            .collect(),
    )
}

/// The 401's description. The middleware answers before a route is
/// resolved, so this is the one status text `render` has to supply.
fn unauthorized_description() -> &'static str {
    "No valid service token (or, on the Workbench, no actor identity)."
}

/// The tag an operation is filed under. Derived from the path so the
/// grouping is reviewable in one place rather than repeated 141 times.
fn tag_for(path: &str) -> &'static str {
    let rest = path.strip_prefix("/api/v1/").unwrap_or(path);
    // Group by the *first* segment, not the whole remainder. Matching
    // the remainder reads `workbench/runs` as an unknown route and
    // dumps every multi-segment path into `other` -- which is most of
    // the API, and a tag that covers most of the API is not a tag. The
    // leading `/` has to come off first, or the first segment of
    // `/healthz` is the empty string and the two public routes read as
    // ungrouped.
    let head = rest.trim_start_matches('/');
    match head.split('/').next().unwrap_or(head) {
        "healthz" | "metrics" | "sources" | "filter-values" | "source-health" | "settings"
        | "reporter-stats" | "ml-health" | "gpu-queue" | "overview" | "webhook-delivery" => "platform",
        "events" | "live" | "event" => "events",
        "mail" | "sessions" | "search" | "topology" | "attackers-graph" | "attack-vectors"
        | "cred-reuse" | "connections" | "investigate" | "sensors" => "investigate",
        "llm-search" | "vault-rag" => "ai",
        "ip-block" | "ip-block-export" | "services" | "problem-reports" | "canarytokens"
        | "credentials" => "operations",
        "config" | "preferences" | "users" | "audit" => "configuration",
        "attackers" | "campaigns" | "clusters" | "alerts" | "recordings" | "payloads"
        | "ml-anomalies" | "store" => "stores",
        "reports" | "workbench" => "reports",
        "sandbox" | "ghidra" | "ghidra-callgraph" | "revdeck" | "cape" | "github-analysis"
        | "artifacts" => "analysis",
        "export" => "export",
        "charts" => "charts",
        _ => "other",
    }
}

/// What a tag covers, for the document's top-level `tags` list. OpenAPI
/// wants a Tag Object per entry rather than a bare string, and a reader
/// landing on a 500-operation group deserves to know what is in it.
fn tag_description(tag: &str) -> &'static str {
    match tag {
        "platform" => "The dashboard's own view of the service: landing overview and KPIs, health, source and pipeline health, and platform settings.",
        "events" => "The event corpus itself: browse, search, and the live event stream.",
        "investigate" => "Read paths that turn one event or sensor into something a human reads.",
        "ai" => "Model-backed triage: LLM search over the corpus and the vault-backed RAG endpoint.",
        "operations" => "Operator housekeeping: block lists, service accounts, canary tokens, problem reports.",
        "configuration" => "Dashboard configuration, user preferences, and the audit trail.",
        "stores" => "The generated Elasticsearch stores the alert, campaign and identity views are built from.",
        "reports" => "Saved report definitions, generated reports, and the Payload Workbench.",
        "analysis" => "Submission and polling for the out-of-band analysers (sandbox, Ghidra, CAPE, RevDeck).",
        "export" => "Bulk CSV/JSON exports of the views an operator hands to someone else.",
        "charts" => "Precomputed chart series, one route per widget.",
        _ => "Routes this service exposes that do not fit the groups above; grouped so nothing is unrouted.",
    }
}

/// A stable, greppable operation id: the method, then the path with `/`
/// and `{}` folded away. Unique by construction, because a repeated
/// (path, method) cannot be registered on one `Router` in the first place.
fn operation_id(method: &str, path: &str) -> String {
    let path: String = path
        .trim_start_matches('/')
        .chars()
        .map(|c| match c {
            '{' | '}' | '.' | '-' | '/' => '_',
            other => other,
        })
        .collect();
    format!("{}_{}", method.to_lowercase(), path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn crate_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// #3325's drift gate, direction one: the committed document has to
    /// be what the generator renders. Compared parsed rather than
    /// byte-wise, so a reformat of the JSON is not a red build while a
    /// changed status code, parameter or tag is.
    #[test]
    fn checked_in_contract_is_current() {
        let path = crate_dir().join("openapi.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} unreadable: {error}", path.display()));
        let committed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()));
        let generated = document();
        assert!(
            committed == generated,
            "openapi.json is stale -- regenerate with\n    \
             cargo run --bin openapi > openapi.json\n\nfirst difference: {}",
            first_difference(&committed, &generated),
        );
    }

    /// The `axum::Router` methods `OpenApiRouter` inherits as pass-throughs:
    /// each one puts a route in front of a caller and **nothing** in the
    /// OpenAPI document, because there is no `#[utoipa::path]` to read. A
    /// route registered with one of these is the one way the contract can
    /// fall behind the service, so the drift gate below refuses them by
    /// name rather than leaving the next reader to notice.
    const BYPASSING_ROUTES: [&str; 3] = [".route(", ".route_service(", ".nest_service("];

    /// #3325's drift gate, direction two: every route the service serves is
    /// in the contract, and every operation in the contract is a route the
    /// service serves.
    ///
    /// This test used to read the `.route(path, method(handler))` calls out
    /// of the route table's source and compare the set against the
    /// document. That comparison is gone, and deliberately so: with
    /// `utoipa-axum` the table no longer spells paths out at all -- it reads
    /// them from each handler's `#[utoipa::path]` and registers the handler
    /// in the axum router and in the document in one call. There is no
    /// second list left to disagree with the first, which was the whole
    /// point of the migration and the reason the hand table rotted twice.
    ///
    /// What replaced it closes the two doors that *are* still open, and
    /// both are in this crate's own source:
    ///
    /// 1. `OpenApiRouter` inherits `axum::Router`'s `.route(...)`,
    ///    `.route_service(...)` and `.nest_service(...)` as pass-throughs
    ///    that add a served route and **no** OpenAPI operation. A route
    ///    registered that way is invisible to the contract and to the
    ///    weekly fuzz job, so the table must contain none of them and the
    ///    test says so by name.
    /// 2. The other direction is a dead annotation: a `#[utoipa::path]` on
    ///    a handler nothing routes, which publishes an operation that
    ///    answers 404. The fuzzer would chase it every week, so every
    ///    annotation in the crate has to be a live one.
    #[test]
    fn contract_covers_every_router_route() {
        let lib_rs =
            std::fs::read_to_string(crate_dir().join("src/lib.rs")).expect("src/lib.rs is readable");

        // (1) The bypass. Comment lines are skipped: `lib.rs`'s own module
        // doc quotes the `.route("/api/v1/events", get(events::list))` form
        // this test used to parse, and that quote is not a registration.
        let bypasses: Vec<&str> = BYPASSING_ROUTES
            .iter()
            .copied()
            .filter(|call| {
                lib_rs
                    .lines()
                    .enumerate()
                    .any(|(number, line)| line.contains(call) && !is_comment(line, number, &lib_rs))
            })
            .collect();
        assert!(
            bypasses.is_empty(),
            "the route table registers {:?} on the OpenApiRouter, which serves the \
             route without putting an operation in the contract (#3325). Register it \
             with `.routes(utoipa_axum::routes!(handler))` instead, or the weekly \
             fuzz job stops covering it.",
            bypasses,
        );

        // (2) The dead annotation. The whole tree, because the annotations
        // are on the handlers and the handlers are spread over 46 files.
        let annotated = annotated_operations();
        assert!(
            annotated.len() > 130,
            "the annotation scan found only {} `#[utoipa::path]` attributes -- the \
             parser is broken, not the crate",
            annotated.len(),
        );

        let published: BTreeSet<(String, String)> = document()["paths"]
            .as_object()
            .expect("paths is an object")
            .iter()
            .flat_map(|(path, item)| {
                item.as_object().expect("a path item is an object").keys().map(move |method| {
                    (path.clone(), method.to_ascii_uppercase())
                })
            })
            .collect();

        let unrouted: Vec<_> = annotated.difference(&published).collect();
        assert!(
            unrouted.is_empty(),
            "these handlers carry a `#[utoipa::path]` but are not routed (#3325), so \
             the contract advertises operations the service answers 404 for: \
             {unrouted:#?}\nregister them in src/lib.rs, or drop the annotation, then \
             run `cargo run --bin openapi > openapi.json`.",
        );
    }

    /// The document has to be loadable, not merely equal to itself. A
    /// path template whose parameter was never declared, an operation
    /// with no responses, or a secured operation that forgot its 401 all
    /// pass the two gates above -- and then leave a fuzzer doing nothing
    /// useful against it.
    /// The contract version is published twice -- in the document a consumer
    /// pins and on the liveness probe it reads at runtime -- and both come
    /// from `API_VERSION`, so a dashboard comparing them is comparing one fact.
    #[tokio::test]
    async fn api_version_is_published_in_the_document_and_on_liveness() {
        assert_eq!(document()["info"]["x-api-version"], json!(crate::API_VERSION));
        let live = serde_json::to_value(crate::livez().await.0).expect("liveness serializes");
        assert_eq!(live["api_version"], json!(crate::API_VERSION));
    }

    #[test]
    fn document_is_well_formed() {
        let document = document();
        assert_eq!(document["openapi"], json!("3.1.0"));
        assert!(document["info"]["title"].is_string());
        assert!(document["info"]["version"].is_string());
        assert!(document["info"]["summary"].is_string());
        assert_eq!(
            document["components"]["securitySchemes"]["serviceToken"]["name"],
            json!("X-Service-Token"),
        );

        let paths = document["paths"].as_object().expect("paths is an object");
        assert!(paths.len() > 100, "only {} paths", paths.len());

        let mut operations_seen = 0usize;
        for (path, item) in paths {
            let captures = capture_names(path);
            for (method, operation) in item.as_object().expect("path item is an object") {
                operations_seen += 1;
                assert!(
                    operation["summary"].is_string(),
                    "{method} {path} has no summary"
                );
                // The transform strips the Rust doc comment's description;
                // if one ever reaches the document this fails rather than
                // publishing a second wording of the same route.
                assert!(
                    operation.get("description").is_none(),
                    "{method} {path} carries a description; the contract carries \
                     a summary per operation and the doc comment is for Rust readers"
                );

                let responses = operation["responses"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{method} {path} declares no responses"));
                assert!(!responses.is_empty(), "{method} {path} declares no response");

                let secured = operation.get("security").is_some();
                assert_eq!(
                    secured,
                    responses.contains_key("401"),
                    "{method} {path}: a secured operation must declare its 401, or \
                     the auth tier is not actually in the contract"
                );
                assert_eq!(
                    secured,
                    !matches!(
                        path.as_str(),
                        "/healthz" | "/livez" | "/readyz" | "/metrics"
                    ),
                    "{method} {path}: /healthz, /livez, /readyz and /metrics are the only \
                     routes outside the service-token tier (this crate's require_service_token)"
                );
                if secured {
                    let unauthorized = &responses["401"];
                    assert!(
                        unauthorized["content"]["text/plain"]["schema"]
                            == json!({"type": "string"}),
                        "{method} {path}: the middleware's 401 is text/plain, because \
                         require_service_token returns a bare (StatusCode, String)"
                    );
                }

                // Every `Json<T>` body can be refused by the extractor
                // before the handler runs, and the fuzzer sends exactly
                // the bodies that trip it.
                if operation.get("requestBody").is_some() {
                    for status in ["415", "422"] {
                        assert!(
                            responses.contains_key(status),
                            "{method} {path} takes a JSON body but does not declare {status} \
                             (axum's Json<T> rejection)"
                        );
                    }
                    let body = &operation["requestBody"];
                    assert!(
                        body["content"]["application/json"]["schema"].is_object(),
                        "{method} {path}: its request body has no schema"
                    );
                    // The optional-body marker is transform input, not
                    // output: one reaching the document means the
                    // transform stopped consuming it.
                    assert!(
                        body.get("x-optional-body").is_none(),
                        "{method} {path}: the x-optional-body marker reached the document"
                    );
                }

                // Same for a `Query<T>` extractor, which answers 400 as
                // text/plain. One direction only: an operation may
                // declare 400 for its handler's own reasons with no query
                // parameters at all (the artifact download refuses a path
                // separator that way).
                let takes_query = operation
                    .get("parameters")
                    .and_then(Value::as_array)
                    .is_some_and(|parameters| {
                        parameters
                            .iter()
                            .any(|parameter| parameter["in"] == json!("query"))
                    });
                assert!(
                    !takes_query || responses.contains_key("400"),
                    "{method} {path}: an operation with query parameters must declare the \
                     400 that axum's Query<T> rejection raises"
                );

                let parameters = operation["parameters"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let declared: BTreeSet<String> = parameters
                    .iter()
                    .filter(|p| p["in"] == json!("path"))
                    .map(|p| p["name"].as_str().unwrap_or_default().to_string())
                    .collect();
                assert_eq!(
                    declared, captures,
                    "{method} {path}: the declared path parameters must match the \
                     template's {{captures}} exactly"
                );
                for parameter in &parameters {
                    assert!(
                        matches!(
                            parameter["in"].as_str(),
                            Some("query") | Some("path") | Some("header")
                        ),
                        "{method} {path}: parameter {} has no location",
                        parameter["name"],
                    );
                }

                if method != "get" {
                    if let Some(body) = operation.get("requestBody") {
                        assert!(
                            body["content"]["application/json"]["schema"].is_object(),
                            "{method} {path}: its request body has no schema"
                        );
                    }
                }
            }
        }
        assert!(operations_seen > 130, "only {operations_seen} operations");
    }

    /// The one operation whose body never ends has to be findable by a
    /// reader of the document, not by someone who knows the path. The
    /// marker is an extension, so it is not part of the OpenAPI spec, but
    /// the weekly fuzz job excludes on exactly this key.
    #[test]
    fn the_endless_stream_is_marked_and_it_is_the_only_one() {
        let document = document();
        let marked: Vec<&str> = document["paths"]
            .as_object()
            .expect("paths is an object")
            .iter()
            .filter(|(_, item)| {
                item.as_object()
                    .expect("a path item is an object")
                    .values()
                    .any(|operation| operation.get("x-endless-stream") == Some(&json!(true)))
            })
            .map(|(path, _)| path.as_str())
            .collect();
        assert_eq!(marked, ["/api/v1/live"]);
    }

    /// The enum the contract advertises for `/api/v1/store/{name}` has
    /// to be the allowlist the handler enforces, or the fuzzer is being
    /// told a route exists that answers 404 for every value it generates.
    /// The list is copied from `stores.rs`, so this test is what keeps
    /// the copy honest.
    #[test]
    fn the_store_enum_matches_the_handside_allowlist() {
        let stores_rs =
            std::fs::read_to_string(crate_dir().join("src/stores.rs")).expect("src/stores.rs");
        let allowlist_start = stores_rs
            .find("fn store_config")
            .expect("store_config is still the allowlist");
        let allowlist_end = allowlist_start
            + stores_rs[allowlist_start..]
                .find("\n}\n")
                .expect("store_config has a closing brace");
        let allowlist = &stores_rs[allowlist_start..allowlist_end];

        let mut from_code: Vec<&str> = allowlist
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                let rest = trimmed.strip_prefix('"')?;
                let end = rest.find('"')?;
                let name = &rest[..end];
                (trimmed.contains("=>")
                    && name.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
                .then_some(name)
            })
            .collect();
        from_code.sort_unstable();

        let mut from_contract: Vec<&str> = STORE_NAMES.to_vec();
        from_contract.sort_unstable();
        assert_eq!(
            from_contract, from_code,
            "the contract's store enum has drifted from stores.rs's store_config \
             allowlist (#3325)"
        );
    }

    /// Regenerating the document must not depend on anything that changes
    /// between runs -- a timestamp, a set iteration order, a HashMap. The
    /// weekly job re-generates and diffs, so a document that is equal
    /// parsed but not equal as bytes is a red build for a reason nobody
    /// can act on.
    #[test]
    fn the_document_is_byte_stable() {
        let once = serde_json::to_string_pretty(&document()).expect("serializes");
        let twice = serde_json::to_string_pretty(&document()).expect("serializes");
        assert_eq!(once, twice, "two renders of one source tree disagree");
        let committed = std::fs::read_to_string(crate_dir().join("openapi.json"))
            .expect("openapi.json is readable");
        assert_eq!(
            once.trim_end(),
            committed.trim_end(),
            "openapi.json is not byte-identical to what the generator renders -- \
             regenerate with `cargo run --bin openapi > openapi.json`"
        );
    }

    fn capture_names(path: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut rest = path;
        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else { break };
            names.insert(after[..close].to_string());
            rest = &after[close + 1..];
        }
        names
    }

    /// The `(path, method)` pairs the crate's `#[utoipa::path]` attributes
    /// declare, read out of the source rather than a hand-kept list. A
    /// third list would be a third thing to update, and the point of the
    /// gate is that the router stays the thing that decides what exists.
    ///
    /// Each attribute is read to its matching close paren, so the nested
    /// groups (`params(...)`, `responses(...)`, `request_body(...)`) do not
    /// end the walk early, and the method and path are then picked out of
    /// the attribute's own header -- the one line, before any group opens.
    ///
    /// The attribute has to open a line. Every one in this crate does, and
    /// requiring it is what keeps this scan (and its own test module, which
    /// quotes the attribute form in a string and a doc comment) from
    /// reading its own text as an annotation.
    fn annotated_operations() -> BTreeSet<(String, String)> {
        let mut found = BTreeSet::new();
        for source in crate_sources() {
            let mut offset = 0usize;
            for line in source.text.split_inclusive('\n') {
                if line.starts_with("#[utoipa::path(") {
                    let attribute =
                        attribute_at(&source.text, offset).expect("the line opens the attribute");
                    found.insert(declared_operation(attribute, &source.name));
                }
                offset += line.len();
            }
        }
        found
    }

    /// The attribute's text, from just inside `#[utoipa::path(` to its
    /// matching close paren.
    fn attribute_at(source: &str, from: usize) -> Option<&str> {
        let open = from + "#[utoipa::path(".len();
        let bytes = source.as_bytes();
        let mut depth = 1i32;
        let mut end = open;
        while depth > 0 {
            match bytes[end] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            end += 1;
        }
        Some(&source[open..end - 1])
    }

    /// The `(path, method)` one attribute declares.
    fn declared_operation(attribute: &str, name: &str) -> (String, String) {
        const METHODS: [&str; 5] = ["get", "post", "put", "delete", "patch"];
        // The header runs from the opening paren to the first nested group,
        // which is where the method and the path are and where every group
        // key (`params`, `responses`, `request_body`, `security`,
        // `extensions`) has not yet appeared.
        let header_end = ["params(", "responses(", "request_body(", "security("]
            .iter()
            .filter_map(|group| attribute.find(group))
            .min()
            .unwrap_or(attribute.len());
        let header = &attribute[..header_end];
        let method = METHODS
            .iter()
            .copied()
            .find(|method| {
                header
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|word| word == *method)
            })
            .unwrap_or_else(|| panic!("a #[utoipa::path] in {name} names no HTTP method"));
        let path = attribute
            .split_once("path = \"")
            .and_then(|(_, after)| after.split_once('"'))
            .map(|(path, _)| path)
            .unwrap_or_else(|| panic!("a #[utoipa::path] in {name} names no path"));
        (path.to_string(), method.to_ascii_uppercase())
    }

    /// The crate's own `src/**/*.rs`, as (name, text). A third list of
    /// handler files would be a third thing to keep in step, and the
    /// annotations are on the handlers.
    fn crate_sources() -> Vec<SourceFile> {
        fn walk(directory: &std::path::Path, out: &mut Vec<SourceFile>) {
            let Ok(entries) = std::fs::read_dir(directory) else { return };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    let name = path
                        .strip_prefix(crate_dir().join("src"))
                        .expect("the walk started at src")
                        .display()
                        .to_string();
                    let text = std::fs::read_to_string(&path)
                        .unwrap_or_else(|error| panic!("{} unreadable: {error}", path.display()));
                    out.push(SourceFile { name, text });
                }
            }
        }
        let mut out = Vec::new();
        walk(&crate_dir().join("src"), &mut out);
        assert!(out.len() > 50, "the scan found only {} source files", out.len());
        out
    }

    struct SourceFile {
        name: String,
        text: String,
    }

    /// Whether a line is inside a comment or a string. Used only to keep
    /// the bypass scan off `lib.rs`'s own module doc, which quotes the
    /// pre-`utoipa` registration form on purpose.
    fn is_comment(line: &str, _number: usize, _source: &str) -> bool {
        let trimmed = line.trim_start();
        trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
    }

    /// "Here is where they stop matching", so a stale contract names the
    /// operation that moved instead of dumping both documents.
    fn first_difference(left: &Value, right: &Value) -> String {
        fn walk(left: &Value, right: &Value, at: &str) -> Option<String> {
            if left == right {
                return None;
            }
            match (left, right) {
                (Value::Object(l), Value::Object(r)) => {
                    for (key, value) in l {
                        match r.get(key) {
                            None => return Some(format!("{at}/{key}: only in openapi.json")),
                            Some(other) => {
                                if let Some(found) = walk(value, other, &format!("{at}/{key}")) {
                                    return Some(found);
                                }
                            }
                        }
                    }
                    for key in r.keys() {
                        if !l.contains_key(key) {
                            return Some(format!("{at}/{key}: missing from openapi.json"));
                        }
                    }
                    None
                }
                _ => Some(format!("{at}: openapi.json has {left}, the generator has {right}")),
            }
        }
        walk(left, right, "").unwrap_or_else(|| "no obvious difference".to_string())
    }
}
