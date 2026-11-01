//! Host filesystem seam (#3582, decision D1 on #3579).
//!
//! The two HTTP services used to read and write the analyzer spools, the
//! analyzer results and the captured payloads straight off bind mounts.
//! That only works while they run on the sensor/Elasticsearch host. Every
//! such access now goes through [`HostFs`]:
//!
//! - **Local** (the default, `HOST_GATEWAY_URL` unset): plain `std::fs`
//!   against the directories the `*_REQUEST_DIR` / `*_RESULTS_DIR` /
//!   `PAYLOAD_DIRS` variables name. This is what the code did before, so the
//!   seam ships before anything moves.
//! - **Remote** (`HOST_GATEWAY_URL` set): the same operations as HTTP calls
//!   to the host gateway, which is this binary in `GATEWAY_MODE`, pinned to
//!   the homeserver (see `host_gateway.rs`). The gateway runs the Local
//!   implementation below, so the rules are enforced in one place.
//!
//! A directory is never named by path on the wire, only by [`Root`] (its
//! variable's name). The gateway resolves that to its own path. File names
//! are a single path component; a symlink that leaves its root is refused;
//! only request roots take writes.
//!
//! The call sites are synchronous (some run inside the Workbench CAS
//! closure, which cannot await), so the remote implementation blocks the
//! calling thread for the HTTP round trip, the same way the `std::fs` call it
//! replaces does. See [`block_on`].

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The header the host gateway reads its credential from.
pub const TOKEN_HEADER: &str = "x-host-gateway-token";
/// Upper bound for one `read`: the payload mirror's own raw cap.
pub const MAX_READ_BYTES: u64 = 32 << 20;
/// Upper bound for the content one `list` call may carry in total.
pub const MAX_LIST_CONTENT_BYTES: u64 = 64 << 20;
/// Upper bound for the number of entries one `list` call returns.
pub const MAX_LIST_ENTRIES: usize = 20_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Every host directory the HTTP services touch, named by the variable that
/// configures it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Root {
    SandboxRequests,
    WindowsSandboxRequests,
    GhostsSandboxRequests,
    GhidraRequests,
    RevdeckRequests,
    CapeRequests,
    GithubAnalysisRequests,
    SandboxResults,
    WindowsSandboxResults,
    GhostsSandboxResults,
    GhidraResults,
    RevdeckResults,
    CapeResults,
}

impl Root {
    pub const ALL: &'static [Root] = &[
        Root::SandboxRequests,
        Root::WindowsSandboxRequests,
        Root::GhostsSandboxRequests,
        Root::GhidraRequests,
        Root::RevdeckRequests,
        Root::CapeRequests,
        Root::GithubAnalysisRequests,
        Root::SandboxResults,
        Root::WindowsSandboxResults,
        Root::GhostsSandboxResults,
        Root::GhidraResults,
        Root::RevdeckResults,
        Root::CapeResults,
    ];

    pub fn env(self) -> &'static str {
        match self {
            Root::SandboxRequests => "SANDBOX_REQUEST_DIR",
            Root::WindowsSandboxRequests => "WINDOWS_SANDBOX_REQUEST_DIR",
            Root::GhostsSandboxRequests => "GHOSTS_SANDBOX_REQUEST_DIR",
            Root::GhidraRequests => "GHIDRA_REQUEST_DIR",
            Root::RevdeckRequests => "REVDECK_REQUEST_DIR",
            Root::CapeRequests => "CAPE_REQUEST_DIR",
            Root::GithubAnalysisRequests => "GITHUB_ANALYSIS_REQUEST_DIR",
            Root::SandboxResults => "SANDBOX_RESULTS_DIR",
            Root::WindowsSandboxResults => "WINDOWS_SANDBOX_RESULTS_DIR",
            Root::GhostsSandboxResults => "GHOSTS_SANDBOX_RESULTS_DIR",
            Root::GhidraResults => "GHIDRA_RESULTS_DIR",
            Root::RevdeckResults => "REVDECK_RESULTS_DIR",
            Root::CapeResults => "CAPE_RESULTS_DIR",
        }
    }

    /// The Linux sandbox has always had in-container defaults; nothing else does.
    fn default_dir(self) -> &'static str {
        match self {
            Root::SandboxRequests => "/sandbox-requests",
            Root::SandboxResults => "/sandbox-results",
            _ => "",
        }
    }

    /// Only the request spools take writes (marker create and cancel).
    pub fn writable(self) -> bool {
        self.env().ends_with("_REQUEST_DIR")
    }

    pub fn from_env_name(name: &str) -> Option<Root> {
        Root::ALL.iter().copied().find(|root| root.env() == name)
    }

    /// This process's own directory for the root, or "" when unconfigured.
    pub fn local_dir(self) -> String {
        std::env::var(self.env())
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| self.default_dir().to_string())
    }
}

/// What `list` and `stat` report about one entry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    /// Milliseconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ms: Option<i64>,
    /// File content, when the `list` filter asked for it and it fit the cap.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub content: Option<Vec<u8>>,
}

impl Entry {
    pub fn modified(&self) -> Option<SystemTime> {
        let ms = u64::try_from(self.modified_ms?).ok()?;
        UNIX_EPOCH.checked_add(Duration::from_millis(ms))
    }

    /// Time since the last modification; zero for a clock skewed into the future.
    pub fn age(&self) -> Option<Duration> {
        Some(self.modified()?.elapsed().unwrap_or_default())
    }
}

mod b64_opt {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|text| base64::engine::general_purpose::STANDARD.decode(text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Whether a root's directory exists, and whether it is writable by mode bits
/// (the check `workbench_domain::directory_usable` has always made).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootInfo {
    pub is_dir: bool,
    pub writable: bool,
}

/// Which entries `list` returns, and whether it carries their content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFilter {
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub suffix: String,
    #[serde(default)]
    pub files_only: bool,
    /// Include the content of each file no larger than this many bytes.
    #[serde(default)]
    pub content_cap: Option<u64>,
}

impl ListFilter {
    pub fn files_with_suffix(suffix: &str) -> Self {
        Self { suffix: suffix.into(), files_only: true, ..Default::default() }
    }

    pub fn with_content(mut self, cap: u64) -> Self {
        self.content_cap = Some(cap);
        self
    }

    fn matches(&self, name: &str) -> bool {
        name.starts_with(&self.prefix) && name.ends_with(&self.suffix)
    }
}

/// A resolved captured payload: where its bytes are and how large it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadRef {
    pub hash: String,
    pub size: u64,
    pub location: PayloadLocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadLocation {
    Local(PathBuf),
    /// Behind the host gateway, addressed by `PayloadRef::hash`.
    Remote,
}

/// One path component, no traversal, no NUL.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

fn modified_ms(meta: &std::fs::Metadata) -> Option<i64> {
    let since = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since.as_millis()).ok()
}

/// The `std::fs` implementation. The gateway serves exactly these functions.
pub mod local {
    use super::*;
    use std::io::Read;

    pub fn dir(root: Root) -> Option<PathBuf> {
        let dir = root.local_dir();
        (!dir.is_empty()).then(|| PathBuf::from(dir))
    }

    fn configured_dir(root: Root) -> io::Result<PathBuf> {
        dir(root).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{} is not configured", root.env())))
    }

    /// `dir/name`, refusing a bad name and a symlink that resolves outside
    /// `dir`. A missing file is returned as a path (create_new needs that).
    pub fn safe_path(root: Root, name: &str) -> io::Result<PathBuf> {
        if !valid_name(name) {
            return Err(invalid("invalid file name"));
        }
        let dir = configured_dir(root)?;
        let path = dir.join(name);
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                let target = std::fs::canonicalize(&path)?;
                let base = std::fs::canonicalize(&dir)?;
                if !target.starts_with(&base) {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "symlink leaves its root"));
                }
            }
        }
        Ok(path)
    }

    fn entry_from(name: String, meta: &std::fs::Metadata) -> Entry {
        Entry { name, size: meta.len(), is_dir: meta.is_dir(), modified_ms: modified_ms(meta), content: None }
    }

    pub fn root_info(root: Root) -> Option<RootInfo> {
        let meta = std::fs::metadata(dir(root)?).ok()?;
        #[cfg(unix)]
        let writable = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o222 != 0
        };
        #[cfg(not(unix))]
        let writable = true;
        Some(RootInfo { is_dir: meta.is_dir(), writable })
    }

    pub fn list(root: Root, filter: &ListFilter) -> io::Result<Vec<Entry>> {
        let dir = configured_dir(root)?;
        let mut out = Vec::new();
        let mut content_budget = MAX_LIST_CONTENT_BYTES;
        for entry in std::fs::read_dir(&dir)?.flatten() {
            if out.len() >= MAX_LIST_ENTRIES {
                break;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
            if !valid_name(&name) || !filter.matches(&name) {
                continue;
            }
            // Follows a symlink only when it stays inside the root.
            let Ok(path) = safe_path(root, &name) else { continue };
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if filter.files_only && !meta.is_file() {
                continue;
            }
            let mut item = entry_from(name, &meta);
            if let Some(cap) = filter.content_cap {
                if meta.is_file() && meta.len() <= cap.min(MAX_READ_BYTES) && meta.len() <= content_budget {
                    if let Ok(body) = std::fs::read(&path) {
                        content_budget = content_budget.saturating_sub(body.len() as u64);
                        item.content = Some(body);
                    }
                }
            }
            out.push(item);
        }
        Ok(out)
    }

    pub fn stat(root: Root, name: &str) -> io::Result<Entry> {
        let path = safe_path(root, name)?;
        Ok(entry_from(name.to_string(), &std::fs::metadata(path)?))
    }

    /// Up to `cap` bytes from the start of the file, and its real size.
    pub fn read_path(path: &Path, cap: u64) -> io::Result<(Vec<u8>, u64)> {
        let mut file = std::fs::File::open(path)?;
        let size = file.metadata()?.len();
        let mut body = Vec::with_capacity(size.min(cap) as usize);
        (&mut file).take(cap.min(MAX_READ_BYTES)).read_to_end(&mut body)?;
        Ok((body, size))
    }

    pub fn read(root: Root, name: &str, cap: u64) -> io::Result<(Vec<u8>, u64)> {
        read_path(&safe_path(root, name)?, cap)
    }

    /// O_CREAT|O_EXCL. `Ok(false)` when the file already existed.
    pub fn create_new(root: Root, name: &str) -> io::Result<bool> {
        if !root.writable() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root is read-only"));
        }
        let path = safe_path(root, name)?;
        match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn remove(root: Root, name: &str) -> io::Result<()> {
        if !root.writable() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root is read-only"));
        }
        std::fs::remove_file(safe_path(root, name)?)
    }

    pub fn resolve_payload(hash: &str) -> Result<PayloadRef, &'static str> {
        let path = crate::payload_paths::resolve_payload_path(hash)?;
        let size = std::fs::metadata(&path).map_err(|_| "captured payload not found")?.len();
        Ok(PayloadRef { hash: hash.to_string(), size, location: PayloadLocation::Local(path) })
    }
}

/// The HTTP client side, talking to a host gateway.
#[derive(Clone, Debug)]
pub struct Remote {
    base: String,
    token: String,
    client: reqwest::Client,
}

/// Runs `future` to completion from synchronous code, wherever that code is:
/// on a multi-thread runtime worker (via `block_in_place`, the production
/// case), on a blocking-pool thread, or outside any runtime. A current-thread
/// runtime cannot block in place, so that case gets a scoped helper thread.
fn block_on<F, T>(make: F) -> T
where
    F: FnOnce(Option<&reqwest::Client>) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + '_>> + Send,
    T: Send,
{
    use tokio::runtime::{Builder, Handle, RuntimeFlavor};
    let fresh = || Builder::new_current_thread().enable_all().build().expect("tokio runtime");
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(make(None)))
        }
        Ok(_) => std::thread::scope(|scope| scope.spawn(|| fresh().block_on(make(None))).join().expect("gateway call")),
        Err(_) => fresh().block_on(make(None)),
    }
}

fn status_error(status: reqwest::StatusCode, body: &str) -> io::Error {
    let kind = match status.as_u16() {
        400 => io::ErrorKind::InvalidInput,
        401 | 403 => io::ErrorKind::PermissionDenied,
        404 => io::ErrorKind::NotFound,
        409 => io::ErrorKind::AlreadyExists,
        _ => io::ErrorKind::Other,
    };
    let reason: String = body.chars().take(200).collect();
    io::Error::new(kind, format!("host gateway {status}: {reason}"))
}

fn transport_error(error: reqwest::Error) -> io::Error {
    io::Error::other(format!("host gateway unreachable: {error}"))
}

impl Remote {
    pub fn new(base: &str, token: &str) -> anyhow::Result<Self> {
        let base = base.trim().trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            anyhow::bail!("HOST_GATEWAY_URL must be an http(s) URL");
        }
        Ok(Self { base, token: token.to_string(), client: Self::client()? })
    }

    fn client() -> anyhow::Result<reqwest::Client> {
        Ok(reqwest::Client::builder().timeout(REQUEST_TIMEOUT).connect_timeout(CONNECT_TIMEOUT).build()?)
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// One request, returning status and body. The shared client is used on
    /// the production runtime; the fallback paths build their own, because a
    /// pooled connection must not outlive the runtime it was opened on.
    fn call(&self, method: reqwest::Method, path: &str, query: &[(&str, String)]) -> io::Result<(reqwest::StatusCode, reqwest::header::HeaderMap, Vec<u8>)> {
        let url = format!("{}{path}", self.base);
        let token = self.token.clone();
        let shared = self.client.clone();
        let query: Vec<(String, String)> = query.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let on_shared = tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        block_on(move |_| {
            Box::pin(async move {
                let client = if on_shared { shared } else { Self::client().map_err(io::Error::other)? };
                let response = client
                    .request(method, url)
                    .header(TOKEN_HEADER, token)
                    .query(&query)
                    .send()
                    .await
                    .map_err(transport_error)?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.bytes().await.map_err(transport_error)?.to_vec();
                Ok((status, headers, body))
            })
        })
    }

    fn json<T: for<'de> Deserialize<'de>>(&self, path: &str, query: &[(&str, String)]) -> io::Result<T> {
        let (status, _, body) = self.call(reqwest::Method::GET, path, query)?;
        if !status.is_success() {
            return Err(status_error(status, &String::from_utf8_lossy(&body)));
        }
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn bytes(&self, path: &str, cap: u64) -> io::Result<(Vec<u8>, u64)> {
        let (status, headers, body) = self.call(reqwest::Method::GET, path, &[("cap", cap.to_string())])?;
        if !status.is_success() {
            return Err(status_error(status, &String::from_utf8_lossy(&body)));
        }
        let size = headers
            .get("x-real-size")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "host gateway omitted x-real-size"))?;
        if body.len() as u64 > cap {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "host gateway exceeded the read cap"));
        }
        Ok((body, size))
    }

    fn name_path(root: Root, op: &str, name: &str) -> io::Result<String> {
        if !valid_name(name) {
            return Err(invalid("invalid file name"));
        }
        Ok(format!("/host/v1/fs/{}/{op}/{}", root.env(), crate::services_control::urlencode(name)))
    }

    pub fn root_info(&self, root: Root) -> Option<RootInfo> {
        self.json(&format!("/host/v1/fs/{}", root.env()), &[]).ok()
    }

    pub fn list(&self, root: Root, filter: &ListFilter) -> io::Result<Vec<Entry>> {
        let mut query = vec![
            ("prefix", filter.prefix.clone()),
            ("suffix", filter.suffix.clone()),
            ("files_only", filter.files_only.to_string()),
        ];
        if let Some(cap) = filter.content_cap {
            query.push(("content_cap", cap.to_string()));
        }
        self.json(&format!("/host/v1/fs/{}/list", root.env()), &query)
    }

    pub fn stat(&self, root: Root, name: &str) -> io::Result<Entry> {
        self.json(&Self::name_path(root, "stat", name)?, &[])
    }

    pub fn read(&self, root: Root, name: &str, cap: u64) -> io::Result<(Vec<u8>, u64)> {
        self.bytes(&Self::name_path(root, "read", name)?, cap)
    }

    pub fn create_new(&self, root: Root, name: &str) -> io::Result<bool> {
        let (status, _, body) = self.call(reqwest::Method::POST, &Self::name_path(root, "create", name)?, &[])?;
        match status.as_u16() {
            201 => Ok(true),
            200 => Ok(false),
            _ => Err(status_error(status, &String::from_utf8_lossy(&body))),
        }
    }

    pub fn remove(&self, root: Root, name: &str) -> io::Result<()> {
        let (status, _, body) = self.call(reqwest::Method::DELETE, &Self::name_path(root, "file", name)?, &[])?;
        if status.is_success() {
            Ok(())
        } else {
            Err(status_error(status, &String::from_utf8_lossy(&body)))
        }
    }

    pub fn resolve_payload(&self, hash: &str) -> Result<PayloadRef, &'static str> {
        if !crate::payload_paths::is_valid_hash(hash) {
            return Err("invalid payload id");
        }
        #[derive(Deserialize)]
        struct Resolved {
            size: u64,
        }
        let resolved: Resolved = self.json(&format!("/host/v1/payload/{hash}"), &[]).map_err(|_| "captured payload not found")?;
        Ok(PayloadRef { hash: hash.to_string(), size: resolved.size, location: PayloadLocation::Remote })
    }

    pub fn read_payload(&self, hash: &str, cap: u64) -> io::Result<(Vec<u8>, u64)> {
        if !crate::payload_paths::is_valid_hash(hash) {
            return Err(invalid("invalid payload id"));
        }
        self.bytes(&format!("/host/v1/payload/{hash}/read"), cap)
    }

    /// Forwards one services-adapter request through the gateway.
    pub async fn adapter(&self, method: &str, path_and_query: &str, timeout: Duration, max_body: usize) -> anyhow::Result<(u16, Vec<u8>)> {
        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let url = format!("{}/host/v1/adapter{path_and_query}", self.base);
        let response = self
            .client
            .request(method, url)
            .header(TOKEN_HEADER, &self.token)
            .timeout(timeout)
            .send()
            .await?;
        let status = response.status().as_u16();
        let mut body = response.bytes().await?.to_vec();
        body.truncate(max_body);
        Ok((status, body))
    }
}

/// Local or remote; picked once at boot.
#[derive(Clone, Debug)]
pub enum HostFs {
    Local,
    Remote(Remote),
}

static HOST: OnceLock<HostFs> = OnceLock::new();

/// The process-wide seam. Unset means Local (tests, workers, today's hosts).
pub fn host() -> &'static HostFs {
    HOST.get_or_init(|| HostFs::Local)
}

/// Client-side configuration: `HOST_GATEWAY_URL` plus `HOST_GATEWAY_TOKEN`
/// (or `_FILE`), and `SERVICES_ADAPTER_URL` for the adapter. The gateway
/// credential must be its own secret, distinct from the BFF and export
/// tokens, so neither of those can reach host files.
pub fn configure_from_env(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&str) -> io::Result<String>,
    other_secrets: &[&str],
) -> anyhow::Result<HostFs> {
    let url = env("HOST_GATEWAY_URL").filter(|v| !v.trim().is_empty());
    let adapter_url = env("SERVICES_ADAPTER_URL").filter(|v| !v.trim().is_empty());
    if adapter_url.is_some() && env("SERVICES_ADAPTER_SOCKET").is_some_and(|v| !v.trim().is_empty()) {
        anyhow::bail!("both SERVICES_ADAPTER_SOCKET and SERVICES_ADAPTER_URL are set; set one");
    }
    let token = crate::trust::secret(env, read, "HOST_GATEWAY_TOKEN")?;
    if url.is_none() && adapter_url.is_none() {
        return Ok(HostFs::Local);
    }
    let token = token.ok_or_else(|| anyhow::anyhow!("HOST_GATEWAY_URL/SERVICES_ADAPTER_URL need HOST_GATEWAY_TOKEN (or _FILE)"))?;
    if other_secrets.iter().any(|other| *other == token) {
        anyhow::bail!("HOST_GATEWAY_TOKEN equals another credential of this service; it must be its own secret");
    }
    match url {
        Some(url) => Ok(HostFs::Remote(Remote::new(&url, &token)?)),
        None => Ok(HostFs::Local),
    }
}

/// Installs the seam. Called once from `main`; a second call is a bug.
pub fn install(fs: HostFs) {
    if HOST.set(fs).is_err() {
        panic!("host_fs::install called twice");
    }
}

impl HostFs {
    pub fn describe(&self) -> String {
        match self {
            HostFs::Local => "local".into(),
            HostFs::Remote(remote) => format!("gateway {}", remote.base()),
        }
    }

    pub fn root_info(&self, root: Root) -> Option<RootInfo> {
        match self {
            HostFs::Local => local::root_info(root),
            HostFs::Remote(remote) => remote.root_info(root),
        }
    }

    /// The root is configured: its variable is set (or it has a default).
    /// Locally that is the old `dir.is_empty()` check; remotely the gateway
    /// is asked whether the directory exists.
    pub fn configured(&self, root: Root) -> bool {
        match self {
            HostFs::Local => !root.local_dir().is_empty(),
            HostFs::Remote(remote) => remote.root_info(root).is_some(),
        }
    }

    pub fn list(&self, root: Root, filter: &ListFilter) -> io::Result<Vec<Entry>> {
        match self {
            HostFs::Local => local::list(root, filter),
            HostFs::Remote(remote) => remote.list(root, filter),
        }
    }

    pub fn stat(&self, root: Root, name: &str) -> io::Result<Entry> {
        match self {
            HostFs::Local => local::stat(root, name),
            HostFs::Remote(remote) => remote.stat(root, name),
        }
    }

    pub fn read(&self, root: Root, name: &str, cap: u64) -> io::Result<(Vec<u8>, u64)> {
        match self {
            HostFs::Local => local::read(root, name, cap),
            HostFs::Remote(remote) => remote.read(root, name, cap),
        }
    }

    /// Reads and parses a JSON file no larger than `cap`.
    pub fn read_json(&self, root: Root, name: &str, cap: u64) -> Option<serde_json::Value> {
        let (body, size) = self.read(root, name, cap).ok()?;
        if size > cap {
            return None;
        }
        serde_json::from_slice(&body).ok()
    }

    pub fn create_new(&self, root: Root, name: &str) -> io::Result<bool> {
        match self {
            HostFs::Local => local::create_new(root, name),
            HostFs::Remote(remote) => remote.create_new(root, name),
        }
    }

    pub fn remove(&self, root: Root, name: &str) -> io::Result<()> {
        match self {
            HostFs::Local => local::remove(root, name),
            HostFs::Remote(remote) => remote.remove(root, name),
        }
    }

    pub fn resolve_payload(&self, hash: &str) -> Result<PayloadRef, &'static str> {
        match self {
            HostFs::Local => local::resolve_payload(hash),
            HostFs::Remote(remote) => remote.resolve_payload(hash),
        }
    }

    /// Up to `cap` bytes of a resolved payload, and its real size.
    pub fn read_payload(&self, payload: &PayloadRef, cap: u64) -> io::Result<(Vec<u8>, u64)> {
        match (&payload.location, self) {
            (PayloadLocation::Local(path), _) => local::read_path(path, cap),
            (PayloadLocation::Remote, HostFs::Remote(remote)) => remote.read_payload(&payload.hash, cap),
            (PayloadLocation::Remote, HostFs::Local) => Err(io::Error::other("remote payload without a host gateway")),
        }
    }
}

/// Encodes bytes for a log line or a test without pulling base64 into callers.
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_one_component() {
        for bad in ["", ".", "..", "a/b", "../x", "/etc/passwd", "a\\b", "a\0b"] {
            assert!(!valid_name(bad), "{bad:?} must be refused");
        }
        assert!(!valid_name(&"x".repeat(256)));
        for good in ["abc.request", "status.json", "linux-1.json", ".hidden"] {
            assert!(valid_name(good));
        }
    }

    #[test]
    fn only_request_roots_are_writable() {
        for root in Root::ALL {
            assert_eq!(root.writable(), root.env().ends_with("_REQUEST_DIR"), "{root:?}");
            assert_eq!(Root::from_env_name(root.env()), Some(*root));
        }
        assert_eq!(Root::from_env_name("PATH"), None);
        assert_eq!(Root::from_env_name("PAYLOAD_DIRS"), None);
    }

    #[test]
    fn entry_content_round_trips_as_base64() {
        let entry = Entry { name: "a".into(), size: 3, content: Some(vec![0, 1, 255]), ..Default::default() };
        let wire = serde_json::to_value(&entry).unwrap();
        assert_eq!(wire["content"], "AAH/");
        assert_eq!(serde_json::from_value::<Entry>(wire).unwrap(), entry);
        let bare = serde_json::to_value(Entry { name: "b".into(), ..Default::default() }).unwrap();
        assert!(bare.get("content").is_none());
    }

    #[test]
    fn configure_defaults_to_local_and_refuses_ambiguity() {
        let read = |_: &str| -> io::Result<String> { Err(io::Error::other("no files")) };
        let none = |_: &str| None;
        assert!(matches!(configure_from_env(&none, &read, &[]).unwrap(), HostFs::Local));

        let no_token = |k: &str| (k == "HOST_GATEWAY_URL").then(|| "http://gw:8083".to_string());
        assert!(configure_from_env(&no_token, &read, &[]).is_err());

        let same = |k: &str| match k {
            "HOST_GATEWAY_URL" => Some("http://gw:8083".to_string()),
            "HOST_GATEWAY_TOKEN" => Some("svc".to_string()),
            _ => None,
        };
        assert!(configure_from_env(&same, &read, &["svc"]).is_err(), "must differ from SERVICE_TOKEN");
        assert!(matches!(configure_from_env(&same, &read, &["other"]).unwrap(), HostFs::Remote(_)));

        let both_adapters = |k: &str| match k {
            "SERVICES_ADAPTER_URL" => Some("http://gw:8083".to_string()),
            "SERVICES_ADAPTER_SOCKET" => Some("/run/a.sock".to_string()),
            "HOST_GATEWAY_TOKEN" => Some("t".to_string()),
            _ => None,
        };
        assert!(configure_from_env(&both_adapters, &read, &[]).is_err());

        let bad_scheme = |k: &str| match k {
            "HOST_GATEWAY_URL" => Some("gw:8083".to_string()),
            "HOST_GATEWAY_TOKEN" => Some("t".to_string()),
            _ => None,
        };
        assert!(configure_from_env(&bad_scheme, &read, &[]).is_err());
    }
}
