//! apiary-backend — Rust service tier of the modernization port (#1608).
//!
//! Serves /api/v1 JSON to the Nitro BFF. This is the foundation slice:
//! health, build info, and the first ES-backed endpoint (overview KPIs).
//! Auth model: the BFF is the only caller and authenticates with a shared
//! service token (SERVICE_TOKEN env), mirroring how the Go dashboard
//! introspects today. Browsers never reach this service directly. An unset
//! SERVICE_TOKEN refuses to boot (#2183) unless APIARY_ALLOW_UNAUTH_DEV=1
//! says otherwise — see the library's `resolve_service_token`.

use apiary_backend::{
    allow_unauth_dev_from_env, audit, build_stamp, config_history, es, fleet, git_revision, host_fs,
    host_gateway, obs, resolve_service_token, trust, worker, AppState,
};
use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,apiary_backend=debug".into()),
        )
        .init();

    // Reject malformed fleet addresses before opening either HTTP listener.
    let _ = (fleet::tunnel_peer_ip(), fleet::tunnel_sensor_ip());

    let es_url = std::env::var("ELASTICSEARCH_URL").unwrap_or_else(|_| "http://127.0.0.1:9200".into());
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".into());
    // #3577: SERVICE_TOKEN or SERVICE_TOKEN_FILE (the swarm secret form).
    let env = |key: &str| std::env::var(key).ok();
    let read = |path: &str| std::fs::read_to_string(path);

    // #3582 (D1): the host gateway is this binary in another role. It serves
    // only /host/v1 and /healthz, with its own token, and needs neither
    // Elasticsearch nor SERVICE_TOKEN, so it branches off before both.
    if host_gateway::mode_from_env(env("GATEWAY_MODE").as_deref())? {
        let state = host_gateway::from_env(&env, &read)?;
        return host_gateway::serve(&listen, state).await;
    }
    let raw_service_token = trust::secret(&env, &read, "SERVICE_TOKEN")?;
    let allow_unauth_dev =
        allow_unauth_dev_from_env(std::env::var("APIARY_ALLOW_UNAUTH_DEV").ok().as_deref());
    let service_token = match resolve_service_token(raw_service_token.as_deref(), allow_unauth_dev)
    {
        Ok(Some(token)) => Some(token.to_string()),
        Ok(None) => {
            // Loud even in the sanctioned case: an operator who set the
            // override should still see exactly what it bought them, and a
            // grep of any container log for E-SERVICE-TOKEN finds both
            // flavors — refusal and opted-in dev — with no green case that
            // merely looks like one (#2183).
            tracing::warn!(
                "[E-SERVICE-TOKEN] SERVICE_TOKEN is unset and APIARY_ALLOW_UNAUTH_DEV=1 is set: \
                 every /api/v1 route accepts unauthenticated requests. Local development only."
            );
            None
        }
        Err(refusal) => return Err(refusal.into()),
    };
    // #3577: the export-only credential, rotation windows, and the actor
    // assertion key and mode. Refuses to boot on anything ambiguous, same
    // posture as the service token above. Names only, never values.
    let others: Vec<String> =
        service_token.iter().cloned().chain(trust::secret(&env, &read, "EXPORT_TOKEN")?).collect();
    let trust = trust::from_env(&env, &read, service_token)?;
    tracing::info!(trust = %trust.describe(), "credentials");
    // #3582 (D1): host files and the services adapter, locally or through
    // the host gateway (HOST_GATEWAY_URL / SERVICES_ADAPTER_URL). Unset is
    // exactly the old behaviour.
    let host = host_fs::configure_from_env(&env, &read, &others.iter().map(String::as_str).collect::<Vec<_>>())?;
    tracing::info!(host = %host.describe(), "host paths");
    host_fs::install(host);
    let audit_path =
        std::env::var("DASHBOARD_AUDIT_FILE").unwrap_or_else(|_| "/state/dashboard-audit.jsonl".into());
    let config_history_path = std::env::var("DASHBOARD_CONFIG_HISTORY_FILE")
        .unwrap_or_else(|_| "/state/dashboard-config-history.jsonl".into());
    // #1972: per-request JSONL lines for filebeat (empty/unset disables —
    // same posture as audit logging, enabled by compose's volume mount).
    let log_file = std::env::var("DASHBOARD_LOG_FILE").unwrap_or_default();

    let state = AppState {
        es: Arc::new(es::Es::connect(&es_url)?),
        trust: Arc::new(trust),
        audit: Arc::new(audit::AuditLogger::new(audit_path)),
        config_history: Arc::new(config_history::ConfigHistory::new(config_history_path)),
        observability: Arc::new(obs::Obs::new(log_file)),
    };

    // Worker loops (#1610): same image, role by WORKER_LOOPS env.
    worker::spawn_enabled(state.clone());

    // The route table itself is the library's, so that the #3325
    // contract is generated from the same `Router` this process serves
    // rather than from a second hand-kept copy of it.
    let app = apiary_backend::router(state);

    let addr: SocketAddr = listen.parse()?;
    // `built` is the one thing that makes a deploy verifiable from outside.
    // Compare it against the merge time; anything else -- a fresh image id, a
    // recreated container, `{"done":true}` -- says the machinery ran, not
    // that this code is what is running. See build.rs. `revision` (#3315) is
    // the same claim without the inference: a timestamp can only be compared,
    // an object name can be looked up.
    tracing::info!(
        %addr,
        %es_url,
        built = %build_stamp(),
        revision = %git_revision(),
        "apiary-backend listening"
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())}
