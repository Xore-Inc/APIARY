//! The host gateway end to end: a real listener, the real `host_fs::Remote`
//! client, temporary directories, and a fake services adapter socket. No
//! process environment is read or written (`Dirs` is explicit).

use super::*;
use crate::host_fs::{HostFs, PayloadLocation, Remote};
use chrono::{Duration as ChronoDuration, Utc};
use std::path::PathBuf;

const TOKEN: &str = "gateway-test-token";

struct Fixture {
    base: String,
    root: PathBuf,
    requests: PathBuf,
    results: PathBuf,
    payloads: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).ok();
    }
}

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "host-gateway-{label}-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn start(token: Rotating<String>, socket: Option<String>) -> Fixture {
    let root = scratch("fx");
    let (requests, results, payloads) = (root.join("requests"), root.join("results"), root.join("payloads"));
    for dir in [&requests, &results, &payloads] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let dirs = Dirs::empty()
        .with_root(Root::GhidraRequests, &requests)
        .with_root(Root::GhidraResults, &results)
        .with_payload_dir(&payloads);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(GatewayState::new(dirs, token, socket));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Fixture { base, root, requests, results, payloads }
}

async fn start_default() -> Fixture {
    start(Rotating::new(TOKEN.to_string()), None).await
}

fn client(fx: &Fixture) -> HostFs {
    HostFs::Remote(Remote::new(&fx.base, TOKEN).unwrap())
}

async fn raw(fx: &Fixture, method: reqwest::Method, path: &str, token: Option<&str>) -> (u16, String) {
    let mut request = reqwest::Client::new().request(method, format!("{}{path}", fx.base));
    if let Some(token) = token {
        request = request.header(host_fs::TOKEN_HEADER, token);
    }
    let response = request.send().await.unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn health_is_open_and_everything_else_needs_the_token() {
    let fx = start_default().await;
    assert_eq!(raw(&fx, reqwest::Method::GET, "/healthz", None).await.0, 200);
    for token in [None, Some(""), Some("wrong"), Some("gateway-test-toke")] {
        let (status, _) = raw(&fx, reqwest::Method::GET, "/host/v1/fs/GHIDRA_REQUEST_DIR", token).await;
        assert_eq!(status, 401, "token {token:?}");
    }
    assert_eq!(raw(&fx, reqwest::Method::GET, "/host/v1/fs/GHIDRA_REQUEST_DIR", Some(TOKEN)).await.0, 200);
    // The gateway serves no /api/v1 at all, with or without its token.
    assert_eq!(raw(&fx, reqwest::Method::GET, "/api/v1/overview/dashboard", Some(TOKEN)).await.0, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_previous_token_works_only_inside_its_window() {
    let open = Rotating { current: "new".to_string(), previous: Some(("old".to_string(), Utc::now() + ChronoDuration::hours(1))) };
    let fx = start(open, None).await;
    assert_eq!(raw(&fx, reqwest::Method::GET, "/host/v1/fs/GHIDRA_REQUEST_DIR", Some("old")).await.0, 200);
    assert_eq!(raw(&fx, reqwest::Method::GET, "/host/v1/fs/GHIDRA_REQUEST_DIR", Some("new")).await.0, 200);

    let closed = Rotating { current: "new".to_string(), previous: Some(("old".to_string(), Utc::now() - ChronoDuration::seconds(1))) };
    let fx = start(closed, None).await;
    assert_eq!(raw(&fx, reqwest::Method::GET, "/host/v1/fs/GHIDRA_REQUEST_DIR", Some("old")).await.0, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn roots_are_named_never_pathed() {
    let fx = start_default().await;
    let fs = client(&fx);
    assert!(fs.configured(Root::GhidraRequests));
    assert!(fs.usable(Root::GhidraRequests, true));
    assert!(!fs.configured(Root::RevdeckRequests), "unset on the gateway");
    for path in ["/host/v1/fs/PATH/list", "/host/v1/fs/PAYLOAD_DIRS/list", "/host/v1/fs/..%2F..%2Fetc/list"] {
        assert_eq!(raw(&fx, reqwest::Method::GET, path, Some(TOKEN)).await.0, 404, "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn traversal_and_escaping_symlinks_are_refused() {
    let fx = start_default().await;
    let outside = scratch("outside");
    std::fs::write(outside.join("secret"), b"host secret").unwrap();
    std::os::unix::fs::symlink(outside.join("secret"), fx.results.join("leak.json")).unwrap();
    std::fs::write(fx.results.join("inside.json"), b"{}").unwrap();
    std::os::unix::fs::symlink(fx.results.join("inside.json"), fx.results.join("alias.json")).unwrap();

    for name in ["%2e%2e", "..%2Fsecret", "a%5Cb", "%2Fetc%2Fpasswd"] {
        let (status, _) = raw(&fx, reqwest::Method::GET, &format!("/host/v1/fs/GHIDRA_RESULTS_DIR/read/{name}"), Some(TOKEN)).await;
        assert!(status == 400 || status == 404, "{name} answered {status}");
    }
    let fs = client(&fx);
    assert_eq!(fs.read(Root::GhidraResults, "leak.json", 100).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs.read(Root::GhidraResults, "../x", 100).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    // A symlink that stays inside its root is followed.
    assert_eq!(fs.read(Root::GhidraResults, "alias.json", 100).unwrap().0, b"{}");
    let names: Vec<String> = fs.list(Root::GhidraResults, &ListFilter::default()).unwrap().into_iter().map(|e| e.name).collect();
    assert!(!names.contains(&"leak.json".to_string()), "list must skip an escaping symlink: {names:?}");
    std::fs::remove_dir_all(&outside).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn create_new_is_exclusive_and_only_request_roots_take_writes() {
    let fx = start_default().await;
    let fs = client(&fx);
    let name = format!("{}.request", "c".repeat(64));
    assert!(fs.create_new(Root::GhidraRequests, &name).unwrap(), "first create");
    assert!(!fs.create_new(Root::GhidraRequests, &name).unwrap(), "second create reports it existed");
    assert!(fx.requests.join(&name).is_file());

    assert_eq!(fs.create_new(Root::GhidraResults, "x.request").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    std::fs::write(fx.results.join("keep.json"), b"{}").unwrap();
    assert_eq!(fs.remove(Root::GhidraResults, "keep.json").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert!(fx.results.join("keep.json").exists());

    fs.remove(Root::GhidraRequests, &name).unwrap();
    assert!(!fx.requests.join(&name).exists());
    assert_eq!(fs.remove(Root::GhidraRequests, &name).unwrap_err().kind(), io::ErrorKind::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn reads_honour_the_cap_and_report_the_real_size() {
    let fx = start_default().await;
    let fs = client(&fx);
    std::fs::write(fx.results.join("big.json"), vec![b'x'; 100]).unwrap();
    let (body, size) = fs.read(Root::GhidraResults, "big.json", 10).unwrap();
    assert_eq!((body.len(), size), (10, 100));
    assert_eq!(fs.read_json(Root::GhidraResults, "big.json", 10), None, "over the cap is not parsed");

    std::fs::write(fx.results.join("a_ghidra.json"), br#"{"ok":1}"#).unwrap();
    std::fs::write(fx.results.join("b_ghidra.json"), vec![b' '; 50]).unwrap();
    std::fs::write(fx.results.join("other.txt"), b"no").unwrap();
    let mut entries = fs.list(Root::GhidraResults, &ListFilter::files_with_suffix("_ghidra.json").with_content(20)).unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["a_ghidra.json", "b_ghidra.json"]);
    assert_eq!(entries[0].content.as_deref(), Some(&br#"{"ok":1}"#[..]));
    assert_eq!(entries[1].content, None, "a file over content_cap comes without content");
    assert!(entries[0].age().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn payloads_resolve_and_read_by_hash_only() {
    let fx = start_default().await;
    let fs = client(&fx);
    let hash = "d".repeat(64);
    std::fs::write(fx.payloads.join(hash.to_uppercase()), b"MZ payload bytes").unwrap();
    let payload = fs.resolve_payload(&hash).unwrap();
    assert_eq!((payload.size, &payload.location), (16, &PayloadLocation::Remote));
    let (head, size) = fs.read_payload(&payload, 2).unwrap();
    assert_eq!((head.as_slice(), size), (&b"MZ"[..], 16));
    assert!(fs.resolve_payload(&"e".repeat(64)).is_err());
    assert!(fs.resolve_payload("not-a-hash").is_err());
    assert_eq!(raw(&fx, reqwest::Method::GET, "/host/v1/payload/..%2F..%2Fetc%2Fpasswd", Some(TOKEN)).await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn distinct_configured_drops_a_root_that_names_the_same_directory() {
    let fx = start_default().await;
    let fs = client(&fx);
    assert_eq!(fs.distinct_configured(&[Root::GhidraRequests, Root::RevdeckRequests, Root::GhidraResults]), [Root::GhidraRequests, Root::GhidraResults]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_works_from_the_blocking_pool_and_from_a_current_thread_runtime() {
    let fx = start_default().await;
    std::fs::write(fx.results.join("s.json"), b"{}").unwrap();
    let base = fx.base.clone();
    let from_pool = tokio::task::spawn_blocking(move || {
        HostFs::Remote(Remote::new(&base, TOKEN).unwrap()).read(Root::GhidraResults, "s.json", 10).unwrap().0
    })
    .await
    .unwrap();
    assert_eq!(from_pool, b"{}");
    let base = fx.base.clone();
    let from_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move { HostFs::Remote(Remote::new(&base, TOKEN).unwrap()).read(Root::GhidraResults, "s.json", 10).unwrap().0 })
    })
    .join()
    .unwrap();
    assert_eq!(from_thread, b"{}");
}

#[tokio::test(flavor = "multi_thread")]
async fn adapter_calls_are_validated_and_forwarded_to_the_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = scratch("adapter");
    let socket = dir.join("adapter.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string();
            log.lock().unwrap().push(line);
            let body = br#"{"services":[{"name":"hp-a","state":"running"}],"ok":true}"#;
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        }
    });
    let fx = start(Rotating::new(TOKEN.to_string()), Some(socket.to_string_lossy().into_owned())).await;
    let remote = Remote::new(&fx.base, TOKEN).unwrap();

    let (status, body) = remote.adapter("GET", "/v1/services", Duration::from_secs(5), 1 << 20).await.unwrap();
    assert_eq!(status, 200);
    assert!(String::from_utf8_lossy(&body).contains("hp-a"));
    assert_eq!(remote.adapter("POST", "/v1/services/hp-a/restart", Duration::from_secs(5), 1 << 20).await.unwrap().0, 200);
    assert_eq!(remote.adapter("GET", "/v1/services/hp-a/logs?lines=50", Duration::from_secs(5), 1 << 20).await.unwrap().0, 200);
    assert_eq!(*seen.lock().unwrap(), ["GET /v1/services HTTP/1.1", "POST /v1/services/hp-a/restart HTTP/1.1", "GET /v1/services/hp-a/logs?lines=50 HTTP/1.1"]);

    for (method, path) in [("POST", "/v1/services/hp-a/rm"), ("POST", "/v1/services/a%20b/stop"), ("GET", "/v1/services/hp-a/logs?lines=5000"), ("GET", "/v1/containers")] {
        let status = remote.adapter(method, path, Duration::from_secs(5), 1 << 20).await.unwrap().0;
        assert!(status == 400 || status == 404 || status == 405, "{method} {path} answered {status}");
    }
    assert_eq!(seen.lock().unwrap().len(), 3, "nothing invalid reached the socket");

    let none = start_default().await;
    let remote = Remote::new(&none.base, TOKEN).unwrap();
    assert_eq!(remote.adapter("GET", "/v1/services", Duration::from_secs(5), 1 << 20).await.unwrap().0, 503);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn gateway_config_refuses_a_shared_or_missing_token() {
    let read = |_: &str| -> io::Result<String> { Err(io::Error::other("no files")) };
    assert!(from_env(&|_: &str| None, &read).is_err(), "no token");
    let shared = |k: &str| match k {
        "HOST_GATEWAY_TOKEN" => Some("same".to_string()),
        "SERVICE_TOKEN" => Some("same".to_string()),
        _ => None,
    };
    assert!(from_env(&shared, &read).is_err(), "equal to SERVICE_TOKEN");
    let export = |k: &str| match k {
        "HOST_GATEWAY_TOKEN" => Some("same".to_string()),
        "EXPORT_TOKEN" => Some("same".to_string()),
        _ => None,
    };
    assert!(from_env(&export, &read).is_err(), "equal to EXPORT_TOKEN");
    let open_window = |k: &str| match k {
        "HOST_GATEWAY_TOKEN" => Some("new".to_string()),
        "HOST_GATEWAY_TOKEN_PREVIOUS" => Some("old".to_string()),
        _ => None,
    };
    assert!(from_env(&open_window, &read).is_err(), "a previous token needs its _UNTIL");
    let own = |k: &str| match k {
        "HOST_GATEWAY_TOKEN" => Some("own".to_string()),
        "SERVICE_TOKEN" => Some("bff".to_string()),
        _ => None,
    };
    assert!(from_env(&own, &read).is_ok());
}

#[test]
fn gateway_mode_values() {
    for off in [None, Some(""), Some("0"), Some("false")] {
        assert!(!mode_from_env(off).unwrap());
    }
    for on in [Some("1"), Some("true"), Some(" 1 ")] {
        assert!(mode_from_env(on).unwrap());
    }
    assert!(mode_from_env(Some("yes")).is_err());
}
