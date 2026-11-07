//! /api/v1/llm-search?q= — semantic search over llm-analysis session
//! summaries (#151), ported from llm_analysis_search.go: embed the
//! operator's free-text query via Ollama (/api/embed, same model and
//! request shape llm-worker uses for the write side), then a bounded ES
//! kNN over the versioned embedding field. Local-only endpoint contract
//! preserved; unreachable Ollama reports unavailable, never a broken
//! page or a fake non-semantic result set.
//!
//! #2291: an optional `source=vault` selector switches the same kNN
//! machinery onto knowledge-vault-search-v1 — the notes #2290's vault-
//! ingest worker renders and embeds — instead of llm-analysis's session
//! summaries. Deliberately a selector, not a merged multi-index query:
//! the two sources are different document lifecycles/owners (#2289), and
//! a selector keeps `available:false`/foreign-embedding accounting exact
//! per source rather than blended across both. `source` defaults to
//! "session" so every existing caller's behavior is byte-for-byte
//! unchanged.

use crate::contract;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::IpAddr;

use crate::AppState;

const SEARCH_K: usize = 10;
const SEARCH_CANDIDATES: usize = 100;

/// Which corpus this request searches. Each variant names its own index
/// and the doc_type value that index's writer stamps — llm-worker's
/// "session" on llm-analysis, the vault-ingest worker's "vault-note" on
/// knowledge-vault-search-v1 (#2291).
#[derive(Clone, Copy)]
pub(crate) struct Source {
    pub(crate) index: &'static str,
    pub(crate) doc_type: &'static str,
    pub(crate) noun: &'static str,
}

const SESSION_SOURCE: Source = Source { index: "llm-analysis", doc_type: "session", noun: "session summaries" };
pub(crate) const VAULT_SOURCE: Source =
    Source { index: "knowledge-vault-search-v1", doc_type: "vault-note", noun: "vault notes" };

fn resolve_source(raw: &str) -> Source {
    match raw {
        "vault" | "vault-note" => VAULT_SOURCE,
        _ => SESSION_SOURCE,
    }
}

/// The kNN request for one query vector (#2117): the filter pins BOTH
/// doc_type and embedding_model, so ranking happens only inside the vector
/// space the query was embedded in. The write side (llm-worker for
/// sessions, vault-worker for notes, #2291) stamps embedding_model on
/// every document precisely because a model switch — an env edit, or a
/// registry tag moving under `:latest` — leaves the index holding two
/// incompatible same-dimension spaces that ES will otherwise happily score
/// against each other: plausible-looking similarities, wrong ranking, no
/// error anywhere. Documents from other models drop out of results until
/// the planned digest-keyed backfill re-embeds them; search() reports that
/// shrink rather than disguising it.
pub(crate) fn knn_body(source: Source, model: &str, vector: &[f64], limit: usize) -> Value {
    json!({
        "knn": {
            "field": "embedding",
            "query_vector": vector,
            "k": limit,
            "num_candidates": SEARCH_CANDIDATES,
            "filter": {"bool": {"filter": [
                {"term": {"doc_type": source.doc_type}},
                {"term": {"embedding_model": model}}
            ]}}
        },
        "_source": {"excludes": ["embedding"]}
    })
}

/// The empty-result body, made explicit about WHY it is empty when the
/// index does hold embeddings from other models (#2117): "no matches" and
/// "matches exist but are not re-embedded yet" need different operator
/// responses. Either way available stays true — this is a filtered-out
/// result, not a failure.
fn empty_hits_response(source: Source, foreign_embeddings: u64) -> Value {
    if foreign_embeddings > 0 {
        json!({
            "available": true,
            "hits": [],
            "foreign_embeddings": foreign_embeddings,
            "note": format!("{foreign_embeddings} {} are embedded by a different model and are excluded until re-embedding", source.noun)
        })
    } else {
        json!({"available": true, "hits": []})
    }
}

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub limit: usize,
    /// #2291: "session" (default) or "vault"/"vault-note". Any other/empty
    /// value falls back to "session" rather than erroring — an unknown
    /// source is a caller bug, not a reason to break existing callers.
    #[serde(default)]
    pub source: String,
}

/// Comma-separated extra hostnames/addresses the operator accepts as the
/// Ollama endpoint, beyond the built-in local set (#3576).
const OLLAMA_ALLOWED_HOSTS_ENV: &str = "OLLAMA_ALLOWED_HOSTS";

/// Mirrors llm-worker's endpoint_is_local() (same `OLLAMA_ALLOWED_HOSTS`).
///
/// The model sees captured attacker data, so the endpoint stays an explicit
/// decision: http or https, bare host (no credentials, path, query or
/// fragment), and the host must be `ollama`, `localhost`, a loopback /
/// private / link-local address, or named in `OLLAMA_ALLOWED_HOSTS`. A
/// Swarm service name or a remote HTTPS endpoint is therefore accepted only
/// when the operator lists it; an unrecognised DNS name is never trusted
/// because of how it looks, since it can resolve anywhere.
pub(crate) fn ollama_url() -> Option<String> {
    let raw = std::env::var("OLLAMA_URL").ok().filter(|value| !value.is_empty())?;
    let allowed = std::env::var(OLLAMA_ALLOWED_HOSTS_ENV).unwrap_or_default();
    ollama_base(&raw, &allowed)
}

fn ollama_base(raw: &str, allowed_hosts: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    if !matches!(url.path(), "" | "/") {
        return None;
    }
    let host = url.host_str()?.to_lowercase();
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let listed = allowed_hosts
        .split(',')
        .map(|entry| entry.trim().trim_matches(|c| c == '[' || c == ']').to_lowercase())
        .any(|entry| !entry.is_empty() && entry == host);
    let local = host == "ollama"
        || host == "localhost"
        || host.parse::<IpAddr>().map(|ip| match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }).unwrap_or(false);
    (local || listed).then(|| raw.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod ollama_base_tests {
    use super::ollama_base;

    #[test]
    fn builtin_local_hosts_are_accepted_over_http_and_https() {
        for url in ["http://ollama:11434", "https://ollama:11434/", "http://localhost:11434", "http://10.8.0.2:11434", "http://[::1]:11434"] {
            assert!(ollama_base(url, "").is_some(), "{url}");
        }
        assert_eq!(ollama_base("http://ollama:11434/", "").as_deref(), Some("http://ollama:11434"));
    }

    #[test]
    fn other_hosts_need_an_explicit_allowlist_entry() {
        assert!(ollama_base("http://tasks.ollama:11434", "").is_none());
        assert!(ollama_base("https://api.openai.com", "").is_none());
        assert!(ollama_base("http://203.0.113.8:11434", "").is_none());
        assert!(ollama_base("http://tasks.ollama:11434", "other, Tasks.Ollama").is_some());
        assert!(ollama_base("https://ollama.example.test", "ollama.example.test").is_some());
        assert!(ollama_base("http://203.0.113.8:11434", "203.0.113.8").is_some());
    }

    #[test]
    fn credentials_paths_queries_and_fragments_are_refused_even_when_listed() {
        let listed = "ollama,tasks.ollama";
        // Built at runtime so no credential-shaped URL literal sits in source.
        let userinfo = ["user", "pw"].join(":");
        let with_user = format!("http://{userinfo}@ollama:11434");
        let with_password_only = format!("http://:{}@ollama:11434", "pw");
        for url in [
            with_user.as_str(),
            with_password_only.as_str(),
            "http://ollama:11434/api/chat",
            "http://ollama:11434?next=https://example.com",
            "http://ollama:11434#frag",
            "ftp://ollama:11434",
        ] {
            assert!(ollama_base(url, listed).is_none(), "{url}");
        }
    }
}

pub(crate) async fn embed(base: &str, model: &str, text: &str) -> anyhow::Result<Vec<f64>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let response = client
        .post(format!("{base}/api/embed"))
        .json(&json!({"model": model, "input": text}))
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("ollama embed: {}", response.status());
    }
    let payload: Value = response.json().await?;
    let vector: Vec<f64> = payload["embeddings"]
        .as_array()
        .and_then(|embeddings| embeddings.first())
        .and_then(|first| first.as_array())
        .map(|values| values.iter().filter_map(|v| v.as_f64()).collect())
        .unwrap_or_default();
    if vector.is_empty() {
        anyhow::bail!("ollama embed: response did not carry exactly one non-empty vector");
    }
    Ok(vector)
}

#[utoipa::path(
    get,
    path = "/api/v1/llm-search",
    summary = "Natural-language search over the corpus, answered by the local model.",
    params(
        ("q" = inline(Option<String>), Query, description = "The question."),
        ("limit" = inline(Option<contract::PositiveCount>), Query, description = "How many hits to summarise."),
        ("source" = inline(Option<String>), Query, description = "\"session\", \"vault\" or \"vault-note\"; an unknown value falls back to session."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn search(State(state): State<AppState>, Query(query): Query<SearchQuery>) -> Json<Value> {
    let mut text = query.q.trim().to_string();
    if text.is_empty() {
        return Json(json!({"available": true, "hits": []}));
    }
    let source = resolve_source(query.source.trim());
    let Some(base) = ollama_url() else {
        return Json(json!({"available": false, "reason": "semantic search is not configured on this deployment"}));
    };
    text.truncate(512);
    let model = std::env::var("LLM_EMBEDDING_MODEL").unwrap_or_else(|_| "nomic-embed-text:latest".into());
    let vector = match embed(&base, &model, &text).await {
        Ok(vector) => vector,
        Err(error) => {
            return Json(json!({"available": false, "reason": format!("embedding the query failed: {error}")}));
        }
    };
    let limit = if query.limit == 0 || query.limit > SEARCH_K { SEARCH_K } else { query.limit };
    match state.es.search_index(&[source.index], knn_body(source, &model, &vector, limit)).await {
        Ok(result) => {
            let hits: Vec<Value> = result["hits"]["hits"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|hit| {
                    let mut doc = hit["_source"].clone();
                    doc["score"] = hit["_score"].clone();
                    doc
                })
                .collect();
            // #2117: distinguish a genuinely empty index from one holding
            // only other models' embeddings — the count query runs just for
            // this report, and only when the filtered search came back empty.
            if hits.is_empty() {
                let foreign = json!({
                    "size": 0,
                    "query": {"bool": {
                        "filter": [{"term": {"doc_type": source.doc_type}}],
                        "must_not": [{"term": {"embedding_model": model}}]
                    }}
                });
                let foreign_count = match state.es.search_index(&[source.index], foreign).await {
                    Ok(count) => count["hits"]["total"]["value"].as_u64().unwrap_or(0),
                    Err(_) => 0,
                };
                return Json(empty_hits_response(source, foreign_count));
            }
            Json(json!({"available": true, "hits": hits}))
        }
        Err(error) => Json(json!({"available": false, "reason": error.to_string()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2117: the kNN filter must pin the query's own model — that term is
    /// what keeps a model switch from ranking across two incompatible
    /// same-dimension vector spaces.
    #[test]
    fn knn_filter_pins_both_doc_type_and_embedding_model() {
        let body = knn_body(SESSION_SOURCE, "nomic-embed-text:latest", &[0.1, 0.2], 5);
        let filter = &body["knn"]["filter"]["bool"]["filter"];
        assert_eq!(filter[0]["term"]["doc_type"], json!("session"));
        assert_eq!(filter[1]["term"]["embedding_model"], json!("nomic-embed-text:latest"));
        assert_eq!(body["knn"]["k"], json!(5));
        // The query vector rides through unchanged.
        assert_eq!(body["knn"]["query_vector"], json!([0.1, 0.2]));
        // Raw vectors never leave the index.
        assert_eq!(body["_source"]["excludes"], json!(["embedding"]));
    }

    #[test]
    fn a_different_configured_model_filters_by_that_model() {
        let body = knn_body(SESSION_SOURCE, "all-minimal:l6", &[0.0], SEARCH_K);
        assert_eq!(body["knn"]["filter"]["bool"]["filter"][1]["term"]["embedding_model"], json!("all-minimal:l6"));
    }

    /// Empty-after-filter is still available:true with zero hits — a
    /// filtered-out result, not an error (#2117 acceptance criterion 3).
    #[test]
    fn empty_without_foreign_embeddings_stays_plain() {
        let body = empty_hits_response(SESSION_SOURCE, 0);
        assert_eq!(body["available"], json!(true));
        assert_eq!(body["hits"], json!([]));
        assert!(body.get("note").is_none());
    }

    #[test]
    fn empty_with_foreign_embeddings_reports_the_exclusion() {
        let body = empty_hits_response(SESSION_SOURCE, 41);
        assert_eq!(body["available"], json!(true));
        assert_eq!(body["hits"], json!([]));
        assert_eq!(body["foreign_embeddings"], json!(41));
        assert!(body["note"].as_str().unwrap_or_default().contains("different model"));
    }

    /// #2117 acceptance criterion: an index holding docs from two different
    /// embedding_model generations must resolve to only the matching
    /// bucket. This crate has no ES mock (search_index() wraps the official
    /// elasticsearch client directly, nothing to substitute), so this
    /// replays the one piece of ES behavior that matters here -- a `term`
    /// clause inside `bool.filter` is an exact-match AND -- against a
    /// synthetic mixed index, using knn_body()'s own filter clauses rather
    /// than a second, hand-duplicated notion of what should match.
    #[test]
    fn knn_filter_excludes_foreign_model_docs_from_a_mixed_index() {
        let docs = [
            ("a", "session", "nomic-embed-text:latest"),
            ("b", "session", "nomic-embed-text:latest"),
            ("c", "session", "nomic-embed-text:v2-drifted"),
            ("d", "session", "nomic-embed-text:v2-drifted"),
        ];
        let body = knn_body(SESSION_SOURCE, "nomic-embed-text:latest", &[0.1, 0.2], SEARCH_K);
        let clauses = body["knn"]["filter"]["bool"]["filter"].as_array().unwrap();
        let survives = |doc_type: &str, model: &str| {
            clauses.iter().all(|clause| {
                let (field, expected) = clause["term"].as_object().unwrap().iter().next().unwrap();
                match field.as_str() {
                    "doc_type" => expected == doc_type,
                    "embedding_model" => expected == model,
                    other => panic!("unexpected filter field {other}"),
                }
            })
        };
        let surviving: Vec<&str> = docs
            .iter()
            .filter(|(_, doc_type, model)| survives(doc_type, model))
            .map(|(id, _, _)| *id)
            .collect();
        assert_eq!(surviving, vec!["a", "b"]);
    }

    // -- #2291: source selector --

    #[test]
    fn resolve_source_defaults_to_session_for_empty_or_unknown_values() {
        assert_eq!(resolve_source("").index, "llm-analysis");
        assert_eq!(resolve_source("bogus").index, "llm-analysis");
        assert_eq!(resolve_source("session").index, "llm-analysis");
    }

    #[test]
    fn resolve_source_routes_vault_aliases_to_the_vault_index() {
        assert_eq!(resolve_source("vault").index, "knowledge-vault-search-v1");
        assert_eq!(resolve_source("vault-note").index, "knowledge-vault-search-v1");
    }

    #[test]
    fn vault_source_knn_filters_by_vault_note_doc_type_not_session() {
        let body = knn_body(VAULT_SOURCE, "nomic-embed-text:latest", &[0.1, 0.2], SEARCH_K);
        assert_eq!(body["knn"]["filter"]["bool"]["filter"][0]["term"]["doc_type"], json!("vault-note"));
    }

    #[test]
    fn vault_source_empty_response_names_vault_notes_not_sessions() {
        let body = empty_hits_response(VAULT_SOURCE, 3);
        assert!(body["note"].as_str().unwrap().contains("vault notes"));
        assert!(!body["note"].as_str().unwrap().contains("session summaries"));
    }
}
