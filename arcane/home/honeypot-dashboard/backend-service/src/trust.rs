//! Who may call /api/v1, and whose actor identity the backend believes
//! (#3577).
//!
//! # The problem this replaces
//!
//! Until #3577 one shared `x-service-token` opened the whole API, and the
//! operator behind a request was whatever `x-actor-username` /
//! `x-actor-role` (or an `actor_*` query field) said. Anyone holding the
//! token could therefore name themselves admin, and the VPS blocklist pull
//! needed that same token, so a host that only reads a text file held a
//! credential that can restart services. A signature made with the bearer
//! token would not have helped: its holder can sign anything.
//!
//! # What this module decides
//!
//! 1. **Scoped credentials.** `SERVICE_TOKEN` is the BFF credential and
//!    reaches every route. `EXPORT_TOKEN` (header `x-export-token`) reaches
//!    exactly `GET /api/v1/ip-block-export` and nothing else: every other
//!    route, the service actions and every actor-sensitive route included,
//!    answers 403 to it. The two must differ.
//! 2. **Verified actor assertions.** The BFF signs a short-lived JWT
//!    (`x-actor-assertion`, alg `EdDSA`) with an Ed25519 private key that is
//!    not the bearer token. The backend holds only the public half, so
//!    neither a stolen bearer token nor the backend's own configuration can
//!    mint an identity. Claims: `sub`, `username`, `role` (`admin` or
//!    `viewer`), `aud` = `apiary-backend`, `iat`, `exp` (at most
//!    [`MAX_LIFETIME_SECS`] after `iat`), and `htm`/`htu`, the request method
//!    and path the assertion was minted for, so a captured assertion cannot
//!    be replayed against a different route.
//! 3. **Rollout mode.** `ACTOR_ASSERTION_MODE` is `off` (default: the
//!    pre-#3577 behaviour, nothing verified), `log` (verify and log what
//!    `enforce` would refuse, change nothing), or `enforce`.
//! 4. **Rotation.** Every credential has a `_PREVIOUS` predecessor accepted
//!    only until its `_PREVIOUS_UNTIL` instant, so an overlap window closes
//!    by itself even if nobody removes the old value.
//! 5. **Actors named in bodies and queries.** Handlers that take an actor
//!    from their own input (`actor_subject`, preferences `subject`, ML
//!    `actor`, ...) bind it through [`ActorBinding`]: overridden with the
//!    verified actor under `enforce`, reported under `log`, as sent under
//!    `off`.
//!
//! Every secret can be given as `NAME` or as `NAME_FILE` (the swarm secret
//! convention from #3590), never both.
//!
//! The decisions are pure functions over headers, method, path and a clock,
//! so their truth tables are tested without a listener; `lib.rs`'s
//! `require_service_token` is the only caller that applies them.

use axum::http::{HeaderMap, Method, StatusCode};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Deserialize;

pub const SERVICE_TOKEN_HEADER: &str = "x-service-token";
pub const EXPORT_TOKEN_HEADER: &str = "x-export-token";
pub const ASSERTION_HEADER: &str = "x-actor-assertion";
pub const ACTOR_USERNAME_HEADER: &str = "x-actor-username";
pub const ACTOR_ROLE_HEADER: &str = "x-actor-role";

/// The `aud` an assertion must carry. A token minted for some other
/// service that happens to trust the same key is not one for this one.
pub const AUDIENCE: &str = "apiary-backend";
/// The longest `exp - iat` accepted. The BFF mints one per call, so a
/// minute is plenty; five tolerates a slow hop without making a captured
/// assertion worth much.
pub const MAX_LIFETIME_SECS: i64 = 300;
/// Clock disagreement tolerated between the BFF host and this one.
pub const CLOCK_SKEW_SECS: i64 = 30;
/// An assertion longer than this is not one the BFF made.
const MAX_ASSERTION_LEN: usize = 4096;

/// The one route the export credential may call.
pub const EXPORT_ROUTE: &str = "/api/v1/ip-block-export";

/// Mutations a `viewer` may perform under `enforce`. Everything else that
/// is not GET/HEAD/OPTIONS needs `admin`. This mirrors the dashboard's own
/// policy (apiary-dashboard `src/server/authorize.ts`: every mutation not in
/// `ADMIN_QUERIES`), keyed by the router's matched path. Deny by default: a
/// route missing here is refused to a viewer, which `log` mode reports
/// before `enforce` turns it on.
pub const VIEWER_MUTATIONS: &[(&str, &str)] = &[
    ("POST", "/api/v1/alerts/{key}/ack"),
    ("POST", "/api/v1/canarytokens"),
    ("POST", "/api/v1/config/validate"),
    ("PUT", "/api/v1/preferences"),
    ("POST", "/api/v1/preferences/reset"),
    ("POST", "/api/v1/problem-reports"),
    ("POST", "/api/v1/reports/preview"),
];

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE {
/// SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) } followed by
/// the 32 key bytes. `openssl pkey -pubout` and Node's
/// `publicKey.export({type: 'spki', format: 'pem'})` both produce exactly
/// this.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionMode {
    Off,
    Log,
    Enforce,
}

impl AssertionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AssertionMode::Off => "off",
            AssertionMode::Log => "log",
            AssertionMode::Enforce => "enforce",
        }
    }
}

/// A credential and, during a rotation, its predecessor with the instant
/// the predecessor stops working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotating<T> {
    pub current: T,
    pub previous: Option<(T, DateTime<Utc>)>,
}

impl<T> Rotating<T> {
    pub fn new(current: T) -> Self {
        Self { current, previous: None }
    }

    /// The values accepted at `now`: the current one, plus the previous one
    /// strictly before its deadline.
    pub fn live(&self, now: DateTime<Utc>) -> impl Iterator<Item = &T> {
        let previous = self
            .previous
            .as_ref()
            .filter(|(_, until)| now < *until)
            .map(|(value, _)| value);
        std::iter::once(&self.current).chain(previous)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The BFF credential, or anyone at all on an APIARY_ALLOW_UNAUTH_DEV
    /// instance.
    Bff,
    /// The export-only credential.
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
}

/// An operator identity whose assertion verified. Under `enforce` it is
/// inserted as a request extension, and `x-actor-username`/`x-actor-role`
/// are rewritten from it, so handlers never see a client-supplied value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedActor {
    pub subject: String,
    pub username: String,
    pub role: Role,
}

/// What the actor gate concluded about one BFF request.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A read that claims no actor. Passes on the bearer token alone.
    Anonymous,
    /// A verified assertion that is allowed this route.
    Actor(VerifiedActor),
    /// Refused, with the status and a reason that names no secret.
    Deny(StatusCode, String),
}

#[derive(Debug, Clone)]
pub struct Trust {
    /// None only on an APIARY_ALLOW_UNAUTH_DEV instance, where every
    /// request is let in as the BFF (#2183).
    pub bff: Option<Rotating<String>>,
    pub export: Option<Rotating<String>>,
    pub mode: AssertionMode,
    pub keys: Option<Rotating<[u8; 32]>>,
}

impl Trust {
    /// The pre-#3577 posture: one token, nothing else. What tests and the
    /// default configuration amount to.
    pub fn bff_only(token: Option<String>) -> Self {
        Self { bff: token.map(Rotating::new), export: None, mode: AssertionMode::Off, keys: None }
    }

    /// Which credential the request presents, or None (401).
    pub fn principal(&self, headers: &HeaderMap, now: DateTime<Utc>) -> Option<Principal> {
        let Some(bff) = &self.bff else {
            return Some(Principal::Bff);
        };
        if matches_any(bff, header(headers, SERVICE_TOKEN_HEADER), now) {
            return Some(Principal::Bff);
        }
        if let Some(export) = &self.export {
            if matches_any(export, header(headers, EXPORT_TOKEN_HEADER), now) {
                return Some(Principal::Export);
            }
        }
        None
    }

    /// The actor gate for a BFF request, independent of the mode: what
    /// `enforce` does with the request. `log` reports a Deny and lets the
    /// request through unchanged; `off` never asks.
    ///
    /// - An assertion that does not verify is a 401, whatever the route.
    /// - No assertion: a mutation, or any request claiming an actor through
    ///   the plain headers, is a 401. A plain read passes as Anonymous.
    /// - A verified viewer on a mutation outside [`VIEWER_MUTATIONS`] is a
    ///   403, whatever `x-actor-role` says.
    pub fn evaluate(
        &self,
        method: &Method,
        path: &str,
        matched: Option<&str>,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) -> Verdict {
        let mutation = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
        let Some(raw) = headers.get(ASSERTION_HEADER) else {
            let claims_actor = headers.contains_key(ACTOR_USERNAME_HEADER)
                || headers.contains_key(ACTOR_ROLE_HEADER);
            if mutation || claims_actor {
                return Verdict::Deny(
                    StatusCode::UNAUTHORIZED,
                    "actor assertion required: send x-actor-assertion signed by the BFF".into(),
                );
            }
            return Verdict::Anonymous;
        };
        let actor = match raw
            .to_str()
            .map_err(|_| "not ASCII".to_string())
            .and_then(|token| self.verify(token, method, path, now))
        {
            Ok(actor) => actor,
            Err(reason) => {
                return Verdict::Deny(
                    StatusCode::UNAUTHORIZED,
                    format!("actor assertion rejected: {reason}"),
                )
            }
        };
        if mutation && actor.role != Role::Admin && !viewer_may(method, matched) {
            return Verdict::Deny(StatusCode::FORBIDDEN, "administrator role required".into());
        }
        Verdict::Actor(actor)
    }

    /// Verify one assertion for one request. The signature is checked
    /// before any claim is read, against the current key and, inside its
    /// window, the previous one.
    pub fn verify(
        &self,
        token: &str,
        method: &Method,
        path: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedActor, String> {
        let keys = self.keys.as_ref().ok_or("no verification key is configured")?;
        if token.len() > MAX_ASSERTION_LEN {
            return Err("too long".into());
        }
        let mut parts = token.split('.');
        let (Some(head), Some(body), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("not a compact JWS (header.payload.signature)".into());
        };
        let header: JwsHeader = decode_json(head).map_err(|e| format!("header: {e}"))?;
        if header.alg != "EdDSA" {
            return Err(format!("alg {:?} is not EdDSA", header.alg));
        }
        let signature = b64url(signature).map_err(|e| format!("signature: {e}"))?;
        let signed = &token.as_bytes()[..head.len() + 1 + body.len()];
        let verified = keys.live(now).any(|key| {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
                .verify(signed, &signature)
                .is_ok()
        });
        if !verified {
            return Err("signature does not verify against a configured key".into());
        }
        let claims: Claims = decode_json(body).map_err(|e| format!("claims: {e}"))?;
        if claims.aud != AUDIENCE {
            return Err(format!("aud {:?} is not {AUDIENCE:?}", claims.aud));
        }
        if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_LIFETIME_SECS {
            return Err(format!("lifetime must be 1..={MAX_LIFETIME_SECS}s"));
        }
        let now = now.timestamp();
        if claims.iat > now + CLOCK_SKEW_SECS {
            return Err("issued in the future".into());
        }
        if now >= claims.exp + CLOCK_SKEW_SECS {
            return Err("expired".into());
        }
        if claims.htm != method.as_str() || claims.htu != path {
            return Err("minted for a different request".into());
        }
        let role = match claims.role.as_str() {
            "admin" => Role::Admin,
            "viewer" => Role::Viewer,
            other => return Err(format!("unknown role {other:?}")),
        };
        let subject = identity(&claims.sub).ok_or("sub is empty or not printable")?;
        let username = identity(&claims.username).ok_or("username is empty or not printable")?;
        Ok(VerifiedActor { subject, username, role })
    }

    /// One boot-log line saying what is configured. Names, never values.
    pub fn describe(&self) -> String {
        fn rotation<T>(name: &str, credential: &Option<Rotating<T>>) -> String {
            match credential {
                None => format!("{name}=unset"),
                Some(Rotating { previous: None, .. }) => format!("{name}=set"),
                Some(Rotating { previous: Some((_, until)), .. }) => {
                    format!("{name}=set+previous-until-{}", until.to_rfc3339())
                }
            }
        }
        format!(
            "{} {} {} actor_assertion_mode={}",
            rotation("service_token", &self.bff),
            rotation("export_token", &self.export),
            rotation("assertion_key", &self.keys),
            self.mode.as_str(),
        )
    }
}

// ---- actors named in bodies and queries ----------------------------------------

/// Which part of the operator's identity a request field claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorField {
    /// The OIDC subject (`sub`).
    Subject,
    /// The OIDC username (`username`), what the backend records and scopes by.
    Username,
    /// `admin` or `viewer`.
    Role,
    /// A display name. An assertion carries none, so under `enforce` a
    /// client-supplied one is dropped and the record falls back to the
    /// verified username.
    DisplayName,
}

impl ActorField {
    fn verified(self, actor: &VerifiedActor) -> &str {
        match self {
            ActorField::Subject => &actor.subject,
            ActorField::Username => &actor.username,
            ActorField::Role => actor.role.as_str(),
            ActorField::DisplayName => "",
        }
    }
}

/// What the trust middleware concluded about the operator, for handlers
/// that also take an actor from their own body or query (`actor_subject`,
/// `actor_username`, preferences `subject`, ML `actor`, ...).
///
/// The middleware attaches one to every request on the BFF credential, in
/// every mode, and handlers read it as an extractor. Each client-named
/// actor field goes through [`ActorBinding::bind`]:
///
/// - `off`: the client's value, as before #3577.
/// - `log`: the client's value, and `[E-ACTOR-ASSERTION]` when `enforce`
///   would treat it differently (it differs from the verified actor, or it
///   names an actor on a request with no assertion).
/// - `enforce`: always the verified actor's value, whatever the client sent
///   (overridden, never merged). A field that names an actor on a request
///   with no verified actor is a 401, the same answer the middleware gives
///   a plain `x-actor-*` header without an assertion.
///
/// Overriding rather than refusing a mismatch is deliberate: the field can
/// then never matter under `enforce`, and a BFF that still sends a display
/// name somewhere keeps working while `log` reports it.
#[derive(Debug, Clone)]
pub struct ActorBinding {
    mode: AssertionMode,
    actor: Option<VerifiedActor>,
    /// `log` only: the middleware already reported that `enforce` would
    /// refuse the whole request, so a field-level line would add nothing.
    refused: bool,
    /// `METHOD route` for the log line. Never a value from the request body.
    route: String,
}

/// A client-named actor `enforce` refuses (401).
#[derive(Debug, PartialEq, Eq)]
pub struct ActorRefusal(pub String);

impl From<ActorRefusal> for (StatusCode, String) {
    fn from(refusal: ActorRefusal) -> Self {
        (StatusCode::UNAUTHORIZED, refusal.0)
    }
}

impl ActorBinding {
    pub fn new(mode: AssertionMode, actor: Option<VerifiedActor>, refused: bool, route: String) -> Self {
        Self { mode, actor, refused, route }
    }

    /// The `off` binding: every client value passes through.
    pub fn off() -> Self {
        Self::new(AssertionMode::Off, None, false, String::new())
    }

    /// The value a handler acts on for one client-named actor field, and the
    /// warning to log, if any. Pure; [`ActorBinding::bind`] logs.
    pub fn decide(&self, field: &str, kind: ActorField, client: &str) -> (Result<String, ActorRefusal>, Option<String>) {
        let named = !client.is_empty();
        match (self.mode, &self.actor) {
            (AssertionMode::Off, _) => (Ok(client.to_string()), None),
            (AssertionMode::Log, actor) => {
                let warning = match actor {
                    _ if self.refused || !named => None,
                    Some(actor) if client != kind.verified(actor) => Some(format!(
                        "log mode: {field} differs from the asserted actor; enforce will use the assertion's"
                    )),
                    Some(_) => None,
                    None => Some(format!(
                        "log mode: enforce would refuse this request: {field} names an actor without an actor assertion"
                    )),
                };
                (Ok(client.to_string()), warning)
            }
            (AssertionMode::Enforce, Some(actor)) => {
                let verified = kind.verified(actor);
                let warning = (named && client != verified)
                    .then(|| format!("{field} differs from the asserted actor; the assertion's was used"));
                (Ok(verified.to_string()), warning)
            }
            (AssertionMode::Enforce, None) if named => (
                Err(ActorRefusal(format!(
                    "actor assertion required: {field} names an actor; send x-actor-assertion signed by the BFF"
                ))),
                None,
            ),
            (AssertionMode::Enforce, None) => (Ok(String::new()), None),
        }
    }

    /// [`ActorBinding::decide`], logging its warning as `[E-ACTOR-ASSERTION]`
    /// (field name and route only, never a value).
    pub fn bind(&self, field: &str, kind: ActorField, client: &str) -> Result<String, ActorRefusal> {
        let (value, warning) = self.decide(field, kind, client);
        if let Some(warning) = warning {
            tracing::warn!(route = %self.route, "[E-ACTOR-ASSERTION] {warning}");
        }
        value
    }

    /// The usual pair: `actor_subject` and `actor_username`.
    pub fn bind_pair(&self, subject: &str, username: &str) -> Result<(String, String), ActorRefusal> {
        Ok((
            self.bind("actor_subject", ActorField::Subject, subject)?,
            self.bind("actor_username", ActorField::Username, username)?,
        ))
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ActorBinding {
    type Rejection = (StatusCode, &'static str);

    /// Missing only if a route was registered outside the trust middleware.
    /// That is a bug, and it fails closed rather than believing the client.
    async fn from_request_parts(parts: &mut axum::http::request::Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<ActorBinding>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "this route is not behind the trust middleware",
        ))
    }
}

/// The export credential's whole surface.
pub fn export_may(method: &Method, matched: Option<&str>) -> bool {
    *method == Method::GET && matched == Some(EXPORT_ROUTE)
}

fn viewer_may(method: &Method, matched: Option<&str>) -> bool {
    matched.is_some_and(|path| {
        VIEWER_MUTATIONS.iter().any(|(m, p)| *m == method.as_str() && *p == path)
    })
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// Constant-time against each accepted value. Every accepted value is
/// compared, so the time taken does not say which one matched.
fn matches_any(credential: &Rotating<String>, presented: &str, now: DateTime<Utc>) -> bool {
    !presented.is_empty()
        && credential.live(now).fold(false, |found, expected| found | ct_eq(expected, presented))
}

fn ct_eq(expected: &str, presented: &str) -> bool {
    let (expected, presented) = (expected.as_bytes(), presented.as_bytes());
    let mut diff = expected.len() ^ presented.len();
    for i in 0..expected.len().min(presented.len()) {
        diff |= (expected[i] ^ presented[i]) as usize;
    }
    diff == 0
}

fn identity(raw: &str) -> Option<String> {
    let value = raw.trim();
    (!value.is_empty() && !value.chars().any(char::is_control)).then(|| value.to_string())
}

#[derive(Deserialize)]
struct JwsHeader {
    alg: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    username: String,
    role: String,
    aud: String,
    iat: i64,
    exp: i64,
    htm: String,
    htu: String,
}

fn b64url(part: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| e.to_string())
}

fn decode_json<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, String> {
    serde_json::from_slice(&b64url(part)?).map_err(|e| e.to_string())
}

/// An Ed25519 public key as PEM (`-----BEGIN PUBLIC KEY-----`) or as the
/// one-line base64 of the same DER, which is easier to carry in an env
/// file. A private key is refused by name: it does not belong on this host.
pub fn parse_public_key(raw: &str) -> Result<[u8; 32], String> {
    if raw.contains("PRIVATE KEY") {
        return Err("this is a private key; the backend takes only the public half".into());
    }
    let body: String = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .flat_map(|line| line.chars().filter(|c| !c.is_whitespace()))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("not base64: {e}"))?;
    match der.split_at_checked(ED25519_SPKI_PREFIX.len()) {
        Some((prefix, key)) if prefix == ED25519_SPKI_PREFIX && key.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(key);
            Ok(out)
        }
        _ => Err("not an Ed25519 SubjectPublicKeyInfo".into()),
    }
}

// ---- configuration -----------------------------------------------------------

/// A boot refusal. Same posture as #2183's E-SERVICE-TOKEN: a
/// misconfigured trust boundary explains itself and the process does not
/// bind, instead of serving with a weaker boundary than the operator meant.
#[derive(Debug)]
pub struct TrustRefusal(pub String);

impl std::fmt::Display for TrustRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[E-TRUST-CONFIG] refusing to start: {} (see docs/BACKEND-TRUST-BOUNDARY.md)", self.0)
    }
}

impl std::error::Error for TrustRefusal {}

/// `NAME` as given, or the contents of the file `NAME_FILE` names with
/// surrounding whitespace (the trailing newline of `echo > file`) removed.
/// An empty `NAME` counts as unset, exactly as before #3577. Setting both
/// is refused rather than resolved, since either precedence rule would
/// silently ignore something the operator wrote.
pub fn secret(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&str) -> std::io::Result<String>,
    name: &str,
) -> Result<Option<String>, TrustRefusal> {
    let file_key = format!("{name}_FILE");
    let direct = env(name).filter(|value| !value.is_empty());
    let file = env(&file_key).filter(|value| !value.trim().is_empty());
    match (direct, file) {
        (Some(_), Some(_)) => Err(TrustRefusal(format!("both {name} and {file_key} are set; set one"))),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let value = read(path.trim())
                .map_err(|e| TrustRefusal(format!("{file_key} names {path:?}, which cannot be read: {e}")))?;
            let value = value.trim();
            if value.is_empty() {
                return Err(TrustRefusal(format!("{file_key} names an empty file")));
            }
            Ok(Some(value.to_string()))
        }
        (None, None) => Ok(None),
    }
}

/// `NAME` plus its rotation predecessor `NAME_PREVIOUS`, which needs an
/// RFC 3339 `NAME_PREVIOUS_UNTIL`: an overlap window without an end is the
/// thing rotation exists to avoid.
fn rotating(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&str) -> std::io::Result<String>,
    name: &str,
    current: Option<String>,
) -> Result<Option<Rotating<String>>, TrustRefusal> {
    let previous_key = format!("{name}_PREVIOUS");
    let until_key = format!("{previous_key}_UNTIL");
    let previous = secret(env, read, &previous_key)?;
    match (current, previous) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(TrustRefusal(format!("{previous_key} is set but {name} is not"))),
        (Some(current), None) => Ok(Some(Rotating::new(current))),
        (Some(current), Some(previous)) => {
            let raw = env(&until_key).filter(|v| !v.trim().is_empty()).ok_or_else(|| {
                TrustRefusal(format!("{previous_key} is set without {until_key} (RFC 3339 end of the overlap window)"))
            })?;
            let until = DateTime::parse_from_rfc3339(raw.trim())
                .map_err(|e| TrustRefusal(format!("{until_key}={raw:?} is not RFC 3339: {e}")))?
                .with_timezone(&Utc);
            Ok(Some(Rotating { current, previous: Some((previous, until)) }))
        }
    }
}

/// Everything except the service token itself, which `main` resolves first
/// through `resolve_service_token` so #2183's refusal text stays exactly
/// what the cutover doc and dashboards grep for.
pub fn from_env(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&str) -> std::io::Result<String>,
    service_token: Option<String>,
) -> Result<Trust, TrustRefusal> {
    let bff = rotating(env, read, "SERVICE_TOKEN", service_token)?;
    let export = rotating(env, read, "EXPORT_TOKEN", secret(env, read, "EXPORT_TOKEN")?)?;
    if let (Some(bff), Some(export)) = (&bff, &export) {
        let bff_values: Vec<&String> = bff.current_and_previous().collect();
        if export.current_and_previous().any(|value| bff_values.contains(&value)) {
            return Err(TrustRefusal(
                "EXPORT_TOKEN (or its _PREVIOUS) equals a SERVICE_TOKEN value; the export credential must be its own secret".into(),
            ));
        }
    }
    let mode = match env("ACTOR_ASSERTION_MODE").as_deref().map(str::trim) {
        None | Some("") | Some("off") => AssertionMode::Off,
        Some("log") => AssertionMode::Log,
        Some("enforce") => AssertionMode::Enforce,
        Some(other) => {
            return Err(TrustRefusal(format!("ACTOR_ASSERTION_MODE={other:?}; use off, log or enforce")))
        }
    };
    let keys = match rotating(env, read, "ACTOR_ASSERTION_PUBLIC_KEY", secret(env, read, "ACTOR_ASSERTION_PUBLIC_KEY")?)? {
        None => None,
        Some(Rotating { current, previous }) => {
            let parse = |name: &str, raw: &str| {
                parse_public_key(raw).map_err(|e| TrustRefusal(format!("{name}: {e}")))
            };
            Some(Rotating {
                current: parse("ACTOR_ASSERTION_PUBLIC_KEY", &current)?,
                previous: match previous {
                    None => None,
                    Some((raw, until)) => Some((parse("ACTOR_ASSERTION_PUBLIC_KEY_PREVIOUS", &raw)?, until)),
                },
            })
        }
    };
    if mode != AssertionMode::Off && keys.is_none() {
        return Err(TrustRefusal(format!(
            "ACTOR_ASSERTION_MODE={} needs ACTOR_ASSERTION_PUBLIC_KEY (or _FILE)",
            mode.as_str()
        )));
    }
    Ok(Trust { bff, export, mode, keys })
}

impl<T> Rotating<T> {
    /// Both values regardless of the clock, for configuration checks.
    fn current_and_previous(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.current).chain(self.previous.as_ref().map(|(value, _)| value))
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Assertion minting for tests: the BFF's half of the contract, in Rust.
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    pub struct Signer(Ed25519KeyPair);

    impl Signer {
        pub fn generate() -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
            Signer(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pkcs8"))
        }

        pub fn public(&self) -> [u8; 32] {
            self.0.public_key().as_ref().try_into().expect("32 bytes")
        }

        /// The public key as the PEM an operator would paste.
        pub fn public_pem(&self) -> String {
            let mut der = ED25519_SPKI_PREFIX.to_vec();
            der.extend_from_slice(&self.public());
            let body = base64::engine::general_purpose::STANDARD.encode(der);
            format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n")
        }

        pub fn sign_claims(&self, claims: &serde_json::Value) -> String {
            self.sign_raw(r#"{"alg":"EdDSA","typ":"JWT"}"#, claims)
        }

        pub fn sign_raw(&self, header: &str, claims: &serde_json::Value) -> String {
            let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let input = format!("{}.{}", enc.encode(header), enc.encode(claims.to_string()));
            let signature = self.0.sign(input.as_bytes());
            format!("{input}.{}", enc.encode(signature.as_ref()))
        }

        /// A well-formed assertion for `method path` issued at `iat`.
        pub fn mint(&self, role: &str, method: &str, path: &str, iat: i64) -> String {
            self.sign_claims(&serde_json::json!({
                "sub": "sub-alice", "username": "alice", "role": role, "aud": AUDIENCE,
                "iat": iat, "exp": iat + 60, "htm": method, "htu": path,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::Signer;
    use super::*;
    use axum::http::HeaderValue;
    use std::collections::HashMap;

    fn at(ts: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(ts, 0).unwrap()
    }

    const NOW: i64 = 1_800_000_000;

    fn trust_with(signer: &Signer, mode: AssertionMode) -> Trust {
        Trust {
            bff: Some(Rotating::new("bff-token".into())),
            export: Some(Rotating::new("export-token".into())),
            mode,
            keys: Some(Rotating::new(signer.public())),
        }
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    // ---- credentials -------------------------------------------------------

    #[test]
    fn each_credential_is_its_own_principal() {
        let trust = trust_with(&Signer::generate(), AssertionMode::Off);
        let now = at(NOW);
        assert_eq!(trust.principal(&headers(&[("x-service-token", "bff-token")]), now), Some(Principal::Bff));
        assert_eq!(trust.principal(&headers(&[("x-export-token", "export-token")]), now), Some(Principal::Export));
        // Each value only counts in its own header: the export token as a
        // service token is no credential at all, and vice versa.
        assert_eq!(trust.principal(&headers(&[("x-service-token", "export-token")]), now), None);
        assert_eq!(trust.principal(&headers(&[("x-export-token", "bff-token")]), now), None);
        assert_eq!(trust.principal(&headers(&[("x-service-token", "bff-token-")]), now), None);
        assert_eq!(trust.principal(&HeaderMap::new(), now), None);
    }

    #[test]
    fn the_export_credential_reaches_one_route() {
        assert!(export_may(&Method::GET, Some(EXPORT_ROUTE)));
        assert!(!export_may(&Method::POST, Some(EXPORT_ROUTE)));
        assert!(!export_may(&Method::POST, Some("/api/v1/services/{name}/{action}")));
        assert!(!export_may(&Method::GET, Some("/api/v1/workbench/runs")));
        assert!(!export_may(&Method::GET, None));
    }

    #[test]
    fn no_token_configured_means_the_dev_override_lets_everyone_in() {
        let trust = Trust::bff_only(None);
        assert_eq!(trust.principal(&HeaderMap::new(), at(NOW)), Some(Principal::Bff));
    }

    #[test]
    fn a_previous_token_works_inside_its_window_and_fails_after_it() {
        let trust = Trust {
            bff: Some(Rotating { current: "new".into(), previous: Some(("old".into(), at(NOW))) }),
            ..Trust::bff_only(None)
        };
        let old = headers(&[("x-service-token", "old")]);
        assert_eq!(trust.principal(&old, at(NOW - 1)), Some(Principal::Bff));
        assert_eq!(trust.principal(&old, at(NOW)), None, "the deadline itself is outside the window");
        assert_eq!(trust.principal(&old, at(NOW + 3600)), None);
        let new = headers(&[("x-service-token", "new")]);
        assert_eq!(trust.principal(&new, at(NOW + 3600)), Some(Principal::Bff));
    }

    // ---- assertions ---------------------------------------------------------

    fn verdict(trust: &Trust, method: Method, path: &str, matched: &str, pairs: &[(&'static str, &str)]) -> Verdict {
        trust.evaluate(&method, path, Some(matched), &headers(pairs), at(NOW))
    }

    #[test]
    fn a_valid_admin_assertion_names_the_actor() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let path = "/api/v1/services/cowrie/restart";
        let token = signer.mint("admin", "POST", path, NOW);
        assert_eq!(
            verdict(&trust, Method::POST, path, "/api/v1/services/{name}/{action}", &[("x-actor-assertion", &token)]),
            Verdict::Actor(VerifiedActor { subject: "sub-alice".into(), username: "alice".into(), role: Role::Admin })
        );
    }

    #[test]
    fn forged_actor_headers_without_an_assertion_are_refused() {
        let trust = trust_with(&Signer::generate(), AssertionMode::Enforce);
        let forged = [("x-actor-username", "root"), ("x-actor-role", "admin")];
        let Verdict::Deny(status, _) = verdict(&trust, Method::GET, "/api/v1/workbench/runs", "/api/v1/workbench/runs", &forged) else {
            panic!("a read claiming an actor without proof must be refused");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let Verdict::Deny(status, _) = verdict(&trust, Method::POST, "/api/v1/services/x/stop", "/api/v1/services/{name}/{action}", &forged) else {
            panic!("a mutation without an assertion must be refused");
        };
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_plain_read_needs_no_assertion() {
        let trust = trust_with(&Signer::generate(), AssertionMode::Enforce);
        assert_eq!(verdict(&trust, Method::GET, "/api/v1/events", "/api/v1/events", &[]), Verdict::Anonymous);
    }

    #[test]
    fn a_missing_assertion_on_a_mutation_is_refused() {
        let trust = trust_with(&Signer::generate(), AssertionMode::Enforce);
        assert!(matches!(
            verdict(&trust, Method::PUT, "/api/v1/preferences", "/api/v1/preferences", &[]),
            Verdict::Deny(StatusCode::UNAUTHORIZED, _)
        ));
    }

    fn rejected(trust: &Trust, token: &str, method: Method, path: &str) -> String {
        match trust.evaluate(&method, path, Some(path), &headers(&[("x-actor-assertion", token)]), at(NOW)) {
            Verdict::Deny(StatusCode::UNAUTHORIZED, reason) => reason,
            other => panic!("expected a 401, got {other:?}"),
        }
    }

    #[test]
    fn an_expired_assertion_is_refused() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        // exp = iat + 60; skew 30. Issued 91s ago means expired 1s past skew.
        let token = signer.mint("admin", "GET", "/api/v1/events", NOW - 91);
        assert!(rejected(&trust, &token, Method::GET, "/api/v1/events").contains("expired"));
        // Inside the skew it still verifies.
        let token = signer.mint("admin", "GET", "/api/v1/events", NOW - 89);
        assert!(matches!(verdict(&trust, Method::GET, "/api/v1/events", "/api/v1/events", &[("x-actor-assertion", &token)]), Verdict::Actor(_)));
    }

    #[test]
    fn an_assertion_from_the_future_or_too_long_lived_is_refused() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let token = signer.mint("admin", "GET", "/api/v1/events", NOW + 120);
        assert!(rejected(&trust, &token, Method::GET, "/api/v1/events").contains("future"));
        let token = signer.sign_claims(&serde_json::json!({
            "sub": "s", "username": "alice", "role": "admin", "aud": AUDIENCE,
            "iat": NOW, "exp": NOW + MAX_LIFETIME_SECS + 1, "htm": "GET", "htu": "/api/v1/events",
        }));
        assert!(rejected(&trust, &token, Method::GET, "/api/v1/events").contains("lifetime"));
    }

    #[test]
    fn an_assertion_signed_by_another_key_is_refused() {
        let trust = trust_with(&Signer::generate(), AssertionMode::Enforce);
        let stranger = Signer::generate();
        let token = stranger.mint("admin", "GET", "/api/v1/events", NOW);
        assert!(rejected(&trust, &token, Method::GET, "/api/v1/events").contains("signature"));
    }

    #[test]
    fn tampered_claims_break_the_signature() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let token = signer.mint("viewer", "GET", "/api/v1/events", NOW);
        let parts: Vec<&str> = token.split('.').collect();
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut claims: serde_json::Value = serde_json::from_slice(&enc.decode(parts[1]).unwrap()).unwrap();
        claims["role"] = "admin".into();
        let forged = format!("{}.{}.{}", parts[0], enc.encode(claims.to_string()), parts[2]);
        assert!(rejected(&trust, &forged, Method::GET, "/api/v1/events").contains("signature"));
    }

    #[test]
    fn alg_none_and_other_algorithms_are_refused() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let claims = serde_json::json!({
            "sub": "s", "username": "alice", "role": "admin", "aud": AUDIENCE,
            "iat": NOW, "exp": NOW + 60, "htm": "GET", "htu": "/api/v1/events",
        });
        for header in [r#"{"alg":"none"}"#, r#"{"alg":"HS256"}"#] {
            let token = signer.sign_raw(header, &claims);
            assert!(rejected(&trust, &token, Method::GET, "/api/v1/events").contains("not EdDSA"), "{header}");
        }
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let unsigned = format!("{}.{}.", enc.encode(r#"{"alg":"EdDSA"}"#), enc.encode(claims.to_string()));
        assert!(rejected(&trust, &unsigned, Method::GET, "/api/v1/events").contains("signature"));
    }

    #[test]
    fn a_wrong_audience_is_refused() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let token = signer.sign_claims(&serde_json::json!({
            "sub": "s", "username": "alice", "role": "admin", "aud": "some-other-service",
            "iat": NOW, "exp": NOW + 60, "htm": "GET", "htu": "/api/v1/events",
        }));
        assert!(rejected(&trust, &token, Method::GET, "/api/v1/events").contains("aud"));
    }

    #[test]
    fn an_assertion_replayed_against_another_route_is_refused() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let token = signer.mint("admin", "GET", "/api/v1/workbench/runs", NOW);
        assert!(rejected(&trust, &token, Method::POST, "/api/v1/services/cowrie/stop").contains("different request"));
        assert!(rejected(&trust, &token, Method::POST, "/api/v1/workbench/runs").contains("different request"));
    }

    #[test]
    fn a_viewer_cannot_escalate_with_the_role_header() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let path = "/api/v1/services/cowrie/stop";
        let token = signer.mint("viewer", "POST", path, NOW);
        assert_eq!(
            verdict(&trust, Method::POST, path, "/api/v1/services/{name}/{action}",
                &[("x-actor-assertion", &token), ("x-actor-role", "admin"), ("x-actor-username", "root")]),
            Verdict::Deny(StatusCode::FORBIDDEN, "administrator role required".into())
        );
    }

    #[test]
    fn a_viewer_keeps_the_mutations_the_dashboard_grants_viewers() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let token = signer.mint("viewer", "PUT", "/api/v1/preferences", NOW);
        assert!(matches!(
            verdict(&trust, Method::PUT, "/api/v1/preferences", "/api/v1/preferences", &[("x-actor-assertion", &token)]),
            Verdict::Actor(VerifiedActor { role: Role::Viewer, .. })
        ));
        let path = "/api/v1/alerts/k1/ack";
        let token = signer.mint("viewer", "POST", path, NOW);
        assert!(matches!(
            verdict(&trust, Method::POST, path, "/api/v1/alerts/{key}/ack", &[("x-actor-assertion", &token)]),
            Verdict::Actor(_)
        ));
    }

    #[test]
    fn an_unknown_role_is_refused() {
        let signer = Signer::generate();
        let trust = trust_with(&signer, AssertionMode::Enforce);
        let token = signer.mint("superuser", "GET", "/api/v1/events", NOW);
        assert!(rejected(&trust, &token, Method::GET, "/api/v1/events").contains("role"));
    }

    #[test]
    fn the_previous_key_verifies_inside_its_window_only() {
        let old = Signer::generate();
        let new = Signer::generate();
        let trust = Trust {
            keys: Some(Rotating { current: new.public(), previous: Some((old.public(), at(NOW + 10))) }),
            ..trust_with(&new, AssertionMode::Enforce)
        };
        let token = old.mint("admin", "GET", "/api/v1/events", NOW);
        assert!(trust.verify(&token, &Method::GET, "/api/v1/events", at(NOW)).is_ok());
        assert!(trust.verify(&token, &Method::GET, "/api/v1/events", at(NOW + 10)).is_err());
    }

    // ---- actors named in bodies and queries ---------------------------------

    fn alice(role: Role) -> Option<VerifiedActor> {
        Some(VerifiedActor { subject: "sub-alice".into(), username: "alice".into(), role })
    }

    fn binding(mode: AssertionMode, actor: Option<VerifiedActor>) -> ActorBinding {
        ActorBinding::new(mode, actor, false, "PUT /api/v1/preferences".into())
    }

    #[test]
    fn off_takes_every_client_value_and_says_nothing() {
        for actor in [None, alice(Role::Viewer)] {
            let off = binding(AssertionMode::Off, actor);
            assert_eq!(off.decide("subject", ActorField::Subject, "sub-bob"), (Ok("sub-bob".into()), None));
            assert_eq!(off.decide("actor", ActorField::Username, ""), (Ok(String::new()), None));
        }
        assert_eq!(ActorBinding::off().decide("role", ActorField::Role, "admin"), (Ok("admin".into()), None));
    }

    #[test]
    fn log_takes_the_client_value_and_warns_where_enforce_would_differ() {
        let log = binding(AssertionMode::Log, alice(Role::Viewer));
        let (value, warning) = log.decide("subject", ActorField::Subject, "sub-bob");
        assert_eq!(value, Ok("sub-bob".into()));
        let warning = warning.expect("a mismatch is reported");
        assert!(warning.contains("subject") && !warning.contains("sub-bob"), "names the field, never the value: {warning}");
        // Matching, or not named at all: nothing to report.
        assert_eq!(log.decide("subject", ActorField::Subject, "sub-alice"), (Ok("sub-alice".into()), None));
        assert_eq!(log.decide("actor", ActorField::Username, ""), (Ok(String::new()), None));
        assert_eq!(log.decide("role", ActorField::Role, "viewer"), (Ok("viewer".into()), None));
        assert!(log.decide("role", ActorField::Role, "admin").1.is_some());
        // A display name has no verified counterpart: any one is reported.
        assert!(log.decide("actor_display_name", ActorField::DisplayName, "Alice").1.is_some());

        // No assertion behind a named actor: enforce would refuse it.
        let anonymous = binding(AssertionMode::Log, None);
        let (value, warning) = anonymous.decide("subject", ActorField::Subject, "sub-bob");
        assert_eq!(value, Ok("sub-bob".into()));
        assert!(warning.unwrap().contains("would refuse"));
        // The middleware already reported this request: one line, not two.
        let refused = ActorBinding::new(AssertionMode::Log, None, true, String::new());
        assert_eq!(refused.decide("subject", ActorField::Subject, "sub-bob"), (Ok("sub-bob".into()), None));
    }

    #[test]
    fn enforce_overrides_every_client_value_with_the_verified_actor() {
        for role in [Role::Viewer, Role::Admin] {
            let enforce = binding(AssertionMode::Enforce, alice(role));
            let (value, warning) = enforce.decide("subject", ActorField::Subject, "sub-bob");
            assert_eq!(value, Ok("sub-alice".into()));
            assert!(warning.is_some());
            assert_eq!(enforce.decide("actor", ActorField::Username, ""), (Ok("alice".into()), None), "filled in when absent");
            assert_eq!(enforce.decide("actor", ActorField::Username, "alice"), (Ok("alice".into()), None));
            assert_eq!(enforce.decide("role", ActorField::Role, "admin").0, Ok(role.as_str().to_string()));
            assert_eq!(enforce.decide("actor_display_name", ActorField::DisplayName, "Bob").0, Ok(String::new()));
            assert_eq!(enforce.bind_pair("sub-bob", "bob"), Ok(("sub-alice".into(), "alice".into())));
        }
    }

    #[test]
    fn enforce_refuses_a_named_actor_with_no_assertion_behind_it() {
        let enforce = binding(AssertionMode::Enforce, None);
        let (value, _) = enforce.decide("subject", ActorField::Subject, "sub-bob");
        let refusal = value.expect_err("must refuse");
        assert!(refusal.0.contains("subject names an actor"), "{refusal:?}");
        assert_eq!(<(StatusCode, String)>::from(refusal).0, StatusCode::UNAUTHORIZED);
        // Naming nobody is fine: the handler sees an empty value, as before.
        assert_eq!(enforce.decide("subject", ActorField::Subject, ""), (Ok(String::new()), None));
    }

    // ---- configuration ------------------------------------------------------

    fn config(pairs: &[(&str, &str)]) -> Result<Trust, TrustRefusal> {
        let env: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let files: HashMap<&str, &str> = [("/run/secrets/export", "export-from-file\n"), ("/run/secrets/empty", "\n")].into();
        let service = env.get("SERVICE_TOKEN").cloned();
        from_env(
            &|key| env.get(key).cloned(),
            &|path| files.get(path).map(|v| v.to_string()).ok_or_else(|| std::io::Error::other("no such file")),
            service,
        )
    }

    fn refusal(pairs: &[(&str, &str)]) -> String {
        config(pairs).expect_err("must refuse").to_string()
    }

    #[test]
    fn the_default_configuration_is_the_old_behaviour() {
        let trust = config(&[("SERVICE_TOKEN", "bff")]).unwrap();
        assert_eq!(trust.mode, AssertionMode::Off);
        assert!(trust.export.is_none() && trust.keys.is_none());
        assert_eq!(trust.bff, Some(Rotating::new("bff".into())));
    }

    #[test]
    fn secrets_can_come_from_files() {
        let trust = config(&[("SERVICE_TOKEN", "bff"), ("EXPORT_TOKEN_FILE", "/run/secrets/export")]).unwrap();
        assert_eq!(trust.export, Some(Rotating::new("export-from-file".into())));
        assert!(refusal(&[("SERVICE_TOKEN", "bff"), ("EXPORT_TOKEN_FILE", "/run/secrets/missing")]).contains("cannot be read"));
        assert!(refusal(&[("SERVICE_TOKEN", "bff"), ("EXPORT_TOKEN_FILE", "/run/secrets/empty")]).contains("empty"));
        assert!(refusal(&[("SERVICE_TOKEN", "bff"), ("EXPORT_TOKEN", "x"), ("EXPORT_TOKEN_FILE", "/run/secrets/export")]).contains("both"));
    }

    #[test]
    fn the_export_token_must_not_be_a_service_token() {
        let message = refusal(&[("SERVICE_TOKEN", "same"), ("EXPORT_TOKEN", "same")]);
        assert!(message.contains("E-TRUST-CONFIG") && message.contains("own secret"), "{message}");
        assert!(refusal(&[
            ("SERVICE_TOKEN", "new"), ("SERVICE_TOKEN_PREVIOUS", "old"),
            ("SERVICE_TOKEN_PREVIOUS_UNTIL", "2030-01-01T00:00:00Z"), ("EXPORT_TOKEN", "old"),
        ]).contains("own secret"));
    }

    #[test]
    fn a_previous_value_needs_an_end_to_its_window() {
        assert!(refusal(&[("SERVICE_TOKEN", "new"), ("SERVICE_TOKEN_PREVIOUS", "old")]).contains("SERVICE_TOKEN_PREVIOUS_UNTIL"));
        assert!(refusal(&[("SERVICE_TOKEN", "new"), ("SERVICE_TOKEN_PREVIOUS", "old"), ("SERVICE_TOKEN_PREVIOUS_UNTIL", "tomorrow")]).contains("RFC 3339"));
        assert!(refusal(&[("SERVICE_TOKEN", "bff"), ("EXPORT_TOKEN_PREVIOUS", "old"), ("EXPORT_TOKEN_PREVIOUS_UNTIL", "2030-01-01T00:00:00Z")]).contains("EXPORT_TOKEN is not"));
        let trust = config(&[("SERVICE_TOKEN", "new"), ("SERVICE_TOKEN_PREVIOUS", "old"), ("SERVICE_TOKEN_PREVIOUS_UNTIL", "2030-01-01T00:00:00+02:00")]).unwrap();
        assert_eq!(trust.bff.unwrap().previous, Some(("old".into(), at(1_893_448_800))));
    }

    #[test]
    fn modes_parse_strictly_and_need_a_key() {
        let signer = Signer::generate();
        let pem = signer.public_pem();
        assert!(refusal(&[("SERVICE_TOKEN", "bff"), ("ACTOR_ASSERTION_MODE", "true")]).contains("off, log or enforce"));
        assert!(refusal(&[("SERVICE_TOKEN", "bff"), ("ACTOR_ASSERTION_MODE", "enforce")]).contains("needs ACTOR_ASSERTION_PUBLIC_KEY"));
        let trust = config(&[("SERVICE_TOKEN", "bff"), ("ACTOR_ASSERTION_MODE", "log"), ("ACTOR_ASSERTION_PUBLIC_KEY", &pem)]).unwrap();
        assert_eq!(trust.mode, AssertionMode::Log);
        assert_eq!(trust.keys.unwrap().current, signer.public());
    }

    #[test]
    fn public_keys_parse_from_pem_or_one_line_base64_and_private_keys_are_refused() {
        let signer = Signer::generate();
        let pem = signer.public_pem();
        assert_eq!(parse_public_key(&pem).unwrap(), signer.public());
        let one_line: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(parse_public_key(&one_line).unwrap(), signer.public());
        // Armor assembled at runtime so the repository's leak scan does not
        // read a test fixture as a committed key. The body is a truncated
        // PKCS#8 prefix, not a key.
        let private = format!("-----BEGIN {0} KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END {0} KEY-----", "PRIVATE");
        assert!(parse_public_key(&private).unwrap_err().contains("private"));
        assert!(parse_public_key("bm90IGEga2V5").unwrap_err().contains("Ed25519"));
    }

    #[test]
    fn describe_names_no_values() {
        let trust = config(&[("SERVICE_TOKEN", "s3cret-bff"), ("EXPORT_TOKEN", "s3cret-export")]).unwrap();
        let line = trust.describe();
        assert!(!line.contains("s3cret"), "{line}");
        assert!(line.contains("export_token=set") && line.contains("actor_assertion_mode=off"), "{line}");
    }
}
