"""
Isolation Forest + HBOS model for point anomaly detection.

Feature engineering is designed for events from:
  - Cowrie (SSH/Telnet honeypot)
  - Dionaea (multi-protocol)
  - Zeek conn/dns/http logs
  - Conpot (ICS)
  - HTTP honeypot

See docs/ml-worker-plan.md §4 and §5 for full feature list.
"""
import ipaddress
import os
import math
import time
import joblib
import numpy as np
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from sklearn.ensemble import IsolationForest
from pyod.models.hbos import HBOS

from models.lifecycle import prune_old_versions, staged_rollback_version, write_version_metadata, _symlink

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
N_FEATURES    = 15
CONTAMINATION = 0.01   # assume ~1% of events are anomalous
N_ESTIMATORS  = 200

# Normalisation ceiling for cmd_count / cmd_count_norm (#277), shared with
# models/lstm_autoencoder.py's featurise_temporal() so both models agree on
# what "a lot of commands in one session" means.
MAX_CMD_COUNT = 200

# Acceptance gate (#65, docs/ml-worker-plan.md §11.1) -- unsupervised
# retraining has no labels to score precision/recall against, so the bar is
# label-free: does the candidate score without error, and does its anomaly
# rate on a holdout slice stay within tolerance of the model it would
# replace, measured on the SAME slice so the comparison isn't confounded by
# traffic changing between two different measurements in time.
HOLDOUT_FRACTION = 0.1   # newest slice of each retrain batch, never trained on
HOLDOUT_MIN       = 50   # floor regardless of fraction, so small batches still get a real check
ACCEPT_TOLERANCE  = 3.0  # candidate's holdout anomaly rate may be at most this many times the reference rate

# Worst-case retrain() cost bound (#62 task 33 -- "bounded HBOS", not just
# "usually fast"). IsolationForest.fit() is O(n_samples * N_ESTIMATORS *
# log(n_samples) * N_FEATURES); HBOS.fit() builds per-feature histograms in
# O(n_samples * N_FEATURES). Both scale linearly in n_samples with no other
# cap upstream -- worker.py's retrain trigger fetches everything matching a
# 24h window across 2 index patterns, which is unbounded on a busy honeypot.
# Capping the actual fit() input here makes the bound a property of the
# model, not something every caller has to remember to enforce.
MAX_TRAIN_SAMPLES = 20_000

# #190: n_jobs=-1 requests one worker per HOST-visible core (this codebase's
# reference deployment has 16), not per the container's actual `cpus: "2.0"`
# cgroup quota -- the same category of mismatch that caused LSTM-AE's real
# thread-pool livelock (models/lstm_autoencoder.py, discovered the same
# session this was audited). IsolationForest.predict()/score_samples() use
# this setting too, not just fit() -- so an oversubscribed pool here sits on
# the hot per-event scoring path, not just the occasional retrain. Bounded to
# match the compose file's cpu limit instead of auto-detecting a core count
# the scheduler will never actually grant this container.
N_JOBS = int(os.getenv("ML_N_JOBS", "2"))

# Known scanner ASNs / Tor exit prefix heuristic (extend as needed)
KNOWN_SCANNER_PREFIXES = {
    "45.33",   # Linode/Akamai scan ranges
    "198.20",  # Shodan
    "66.240",  # Shodan
    "71.6",    # Shodan
    "80.82",   # Shodan
    "89.248",  # Shodan
    "93.120",  # Censys
    "162.142", # Censys
    "167.94",  # Censys
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    probs = [v / len(data) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def _str_entropy(s: str) -> float:
    return _shannon_entropy(s.encode("utf-8", errors="replace"))


def _ts_to_hour(ts_str: Optional[str]) -> int:
    if not ts_str:
        return 0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return 0


def _ts_to_dow(ts_str: Optional[str]) -> int:
    if not ts_str:
        return 0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.weekday()
    except Exception:
        return 0


def _proto_enc(proto: Optional[str]) -> int:
    return {"tcp": 0, "udp": 1, "icmp": 2}.get((proto or "").lower(), 3)


def _is_known_scanner(ip: Optional[str]) -> int:
    if not ip:
        return 0
    prefix = ".".join(ip.split(".")[:2])
    return 1 if prefix in KNOWN_SCANNER_PREFIXES else 0


# ------------------------------------------------------------------
# Real-document field extraction (#62 task 32/33).
#
# A real honeypot-v2-*/suricata-v2-* document nests everything under
# honeypot.*/source.*/destination.*/network.*/user.*/suricata.eve.* --
# see docs/ml-worker-plan.md §5.3 and ml-worker/tests/fixtures.py for the
# ground-truth shape each helper below reads, cited to the actual sensor
# logging source (not assumed). ECS-promoted fields are read first where
# they exist (the one place field names are consistent across sensors);
# per-sensor honeypot.* fields fill in what the geoip-honeypot ingest
# pipeline doesn't promote (see issue #132 for why some of that is a
# pipeline gap rather than something readable from here at all).
# ------------------------------------------------------------------

def _parse_home_net(raw: str) -> list:
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.warning(f"ML_HOME_NET: ignoring unparseable entry {part!r}")
    return nets


# #174: our own address(es), so _resolve_flow_sides() below can tell "the
# honeypot itself" apart from "the actual remote party" on ECS source/
# destination fields. Same CIDR-list convention as vps/.env.example's
# SURICATA_HOME_NET. Empty by default -- unset means every _get_ip()/
# _get_port() call keeps its pre-#174 behaviour (source=remote,
# destination=local), which is still correct for every sensor except
# Suricata netflow (see below).

# #1959: ML_HOME_NET carried only the VPS WAN address, so every other address
# we own -- loopback, the WireGuard tunnel between the VPS and the homeserver,
# and the home LAN -- read as a remote party. Measured consequence: on the
# largest alert day on record, 127.0.0.1 was the single biggest "source",
# 3,204 of 6,669 alerts. An alert whose src_ip an operator cannot act on is
# not an alert.
#
# These are defaults rather than required configuration because they are
# properties of the deployment shape, not of a particular install: this stack
# always has a WireGuard tunnel and a home LAN behind it, and loopback is never
# a remote attacker anywhere. ML_LOCAL_NETS overrides the list for a deployment
# whose honeypots legitimately live inside RFC1918 and should be scored.
#
# The deployment-specific public address stays in ML_HOME_NET, which the
# install already writes from PUBLIC_IP -- kept separate so a widened default
# here can never quietly drop it.
DEFAULT_LOCAL_NETS = ",".join([
    "127.0.0.0/8",      # loopback
    "::1/128",          # loopback, v6
    "169.254.0.0/16",   # link-local
    "10.8.0.0/24",      # WireGuard: VPS <-> homeserver
    "10.0.0.0/8",       # RFC1918
    "172.16.0.0/12",    # RFC1918, and the Docker bridge ranges
    "192.168.0.0/16",   # RFC1918, home LAN
])

# `or DEFAULT_LOCAL_NETS`, not a getenv default: compose passes
# "${ML_LOCAL_NETS:-}", so the variable is *set to an empty string* when the
# operator has not configured one, and os.getenv would then return "" rather
# than the default -- silently disabling the whole exclusion. Treating empty
# as unconfigured is what makes the safe value actually reach production.
HOME_NET = (
    _parse_home_net(os.getenv("ML_HOME_NET", ""))
    + _parse_home_net(os.getenv("ML_LOCAL_NETS", "").strip() or DEFAULT_LOCAL_NETS)
)


def _in_home_net(ip: str) -> bool:
    if not ip or not HOME_NET:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in HOME_NET)


def is_our_own_address(ip: str) -> bool:
    """True when `ip` is an address this deployment owns.

    Exposed for worker.py's alert path. Same set `_resolve_flow_sides()` uses
    to tell our side of a flow from the remote one -- deliberately one list, so
    the two cannot disagree about what "us" means.
    """
    return _in_home_net(ip)


def _resolve_flow_sides(src: dict) -> tuple:
    """Returns (remote, local) ECS source/destination dicts -- 'remote' is
    the non-us side of a flow, 'local' is our own side.

    Found live (#174): Suricata's netflow event type logs BOTH directions
    of a flow as separate records, and ECS source/destination reflect
    literal packet direction, not attacker/victim -- so for roughly half
    of all netflow records, `source.ip` is the honeypot's OWN address, not
    the remote scanner's. Since _get_ip()/_get_port() previously trusted
    source/destination positionally, session_features.py's per-IP rolling
    window (unique_ports_1h, #277) was bucketing every distinct external
    scanner that touched this host under one shared key (our own IP) for
    that half of events -- confirmed live: unique_ports_1h readings in the
    thousands within a single retrain batch, the actual driver of
    isolation_forest_hbos's holdout-anomaly-rate gate rejecting every
    retrain (#65's acceptance bar) rather than a sign the model itself was
    bad. Also fed a wrong src_ip straight into worker.py's anomaly
    metadata, which is operator-facing (the dashboard's alert table).

    Falls back to (source, destination) -- i.e. no swap -- when
    ML_HOME_NET is unset or neither/both sides match it: every non-netflow
    sensor's normal case, where source genuinely is the remote party.
    """
    source = src.get("source") or {}
    dest = src.get("destination") or {}
    if _in_home_net(source.get("ip") or "") and not _in_home_net(dest.get("ip") or ""):
        return dest, source
    return source, dest


def _get_ip(src: dict) -> str:
    remote, _ = _resolve_flow_sides(src)
    ip = remote.get("ip")
    if ip:
        return ip
    hp = src.get("honeypot") or {}
    if hp.get("src_ip"):
        return hp["src_ip"]
    eve = ((src.get("suricata") or {}).get("eve")) or {}
    return eve.get("src_ip") or ""


def _parse_port(value) -> int:
    """int(), but it also understands a Go listen address (#2978).

    beelzebub's `Init service` records write honeypot.port as the address it
    bound -- ":8880", ":389" -- and the honeypot ingest pipeline copied
    honeypot.port straight into destination.port. destination.port maps as
    `integer`, so Elasticsearch dropped the value from the index and no
    aggregation could see it, but the string stayed in `_source`, which is
    what this worker reads. A bare int(":8880") is a ValueError, and on the
    retrain path (models.session_features, which has no per-event guard of
    its own) it took the whole worker down: 366 crashes in two hours over
    fifteen bad documents in a 20 000-event training window.

    ":8880" is a *known* representation of a port, not junk, so it is parsed
    rather than tolerated. Anything genuinely uninterpretable still raises,
    exactly as before -- #171 deliberately keeps extract_features() raising
    on a malformed field so the caller can quarantine the event as
    reviewable rather than silently score it on a wrong value.

    The pipeline now normalises this at ingest too (elasticsearch-setup.sh's
    norm_port), but documents already indexed keep the old shape forever.
    """
    if isinstance(value, str) and ":" in value:
        # rsplit, so an IPv6 host part ("[::]:8880") cannot swallow the port.
        value = value.rsplit(":", 1)[1].strip()
    return int(value)


def _get_port(src: dict) -> int:
    _, local = _resolve_flow_sides(src)
    if local.get("port") is not None:
        return _parse_port(local["port"])
    hp = src.get("honeypot") or {}
    if hp.get("dst_port") is not None:
        return _parse_port(hp["dst_port"])
    if hp.get("port") is not None:
        return _parse_port(hp["port"])
    eve = ((src.get("suricata") or {}).get("eve")) or {}
    if eve.get("dest_port") is not None:
        return _parse_port(eve["dest_port"])
    return 0


def _get_transport_proto(src: dict) -> Optional[str]:
    """Transport-layer protocol (tcp/udp/icmp) for _proto_enc -- distinct
    from application-layer identifiers like Cowrie's "ssh", multipot's
    "vnc"/"redis"/"mysql"/etc (its own `proto` field is the *application*
    protocol -- confirmed by reading multipot/protocols.go's actual
    log.emit() call sites, not assumed), or Conpot's "modbus" data_type --
    none of which _proto_enc was ever meant to encode."""
    net = src.get("network") or {}
    if net.get("transport"):
        return net["transport"]
    hp = src.get("honeypot") or {}
    conn = hp.get("connection")
    if isinstance(conn, dict) and conn.get("transport"):
        return conn["transport"]  # Dionaea: connection.protocol is app-layer (e.g. "smbd"); .transport is tcp/udp
    if hp.get("eventid", "").startswith("cowrie."):
        return "tcp"  # SSH/Telnet are structurally TCP-only; Cowrie's own log never states it
    if hp.get("sensor") == "http-honeypot":
        return "tcp"  # HTTP(S) is structurally TCP-only
    if "event" in hp and "eventid" not in hp:
        return "tcp"  # multipot's own event shape; every one of its listeners is TCP (main.go has no UDP path)
    # Conpot exposes neither a transport field nor a fixed single transport
    # across its personas (SNMP is UDP, everything else here is TCP) -- no
    # honest inference available, left unset.
    return net.get("protocol") or hp.get("protocol")


def _get_dst_ip(src: dict) -> str:
    """Our side's address of the flow (#1968): which decoy drew the alert.

    The positional-swap rules of _resolve_flow_sides() decide what "our"
    means exactly as they do for _get_port() -- on netflow records whose
    ECS sides are literal packet direction, the honeypot's own address is
    the honest answer to "what was attacked"; the fallback chains mirror
    _get_ip()'s for the sensors that never promote destination namespaces.
    """
    _, local = _resolve_flow_sides(src)
    ip = local.get("ip")
    if ip:
        return ip
    hp = src.get("honeypot") or {}
    if hp.get("dst_ip"):
        return hp["dst_ip"]
    eve = ((src.get("suricata") or {}).get("eve")) or {}
    return eve.get("dest_ip") or ""


def _get_src_port(src: dict) -> int:
    """The remote side's source port (#1968), mirroring _get_ip()'s side.

    0 (not None) keeps the convention _get_port() established for ports no
    sensor reported -- a typed integer column that dashboards can range-
    filter without null-handling.
    """
    remote, _ = _resolve_flow_sides(src)
    if remote.get("port") is not None:
        return _parse_port(remote["port"])
    hp = src.get("honeypot") or {}
    if hp.get("src_port") is not None:
        return _parse_port(hp["src_port"])
    eve = ((src.get("suricata") or {}).get("eve")) or {}
    if eve.get("src_port") is not None:
        return _parse_port(eve["src_port"])
    return 0


def _get_username(src: dict) -> str:
    user = (src.get("user") or {}).get("name")
    if user:
        return user
    return (src.get("honeypot") or {}).get("username") or ""


def _get_password(src: dict) -> str:
    return (src.get("honeypot") or {}).get("password") or ""


def _get_duration(src: dict) -> float:
    # Only Cowrie's cowrie.session.closed event carries this; every other
    # source has no session-duration concept in its own log format.
    return float((src.get("honeypot") or {}).get("duration") or 0.0)


@dataclass
class RetrainResult:
    """Evidence for one retrain() call -- accepted or not, and why. Returned
    to the caller (worker.py) so it can be written to ml-worker-metrics
    (#65, docs/ml-worker-plan.md §11.4); also embedded verbatim in the
    accepted version's metadata sidecar (lifecycle.write_version_metadata)."""
    accepted: bool
    reason: str
    train_samples: int
    holdout_samples: int
    anomaly_rate_new: float
    anomaly_rate_previous: Optional[float]
    # #3097 PR-1 step 4: forensic evidence for A4 (training slice covers the
    # day) -- per-index sample counts and the distinct @timestamp hours seen,
    # so "was this retrain trained on a skewed slice" is one `cat *.meta.json`
    # instead of re-deriving it from HBOS bin edges (§1.3 of the research doc).
    train_index_counts: Optional[dict] = None
    train_hours: Optional[list] = None


def _accept_decision(candidate_rate: float, previous_rate: Optional[float]) -> tuple:
    """The acceptance policy itself (#65, docs/ml-worker-plan.md §11.1),
    isolated from fitting/scoring so it's testable with plain floats rather
    than needing a real stochastic model fit to land on a particular
    outcome. Returns (accepted, reason)."""
    reference_rate = previous_rate if previous_rate is not None else CONTAMINATION
    ceiling = max(reference_rate, CONTAMINATION) * ACCEPT_TOLERANCE
    if candidate_rate <= ceiling:
        return True, "accepted"
    return False, (
        f"holdout anomaly rate {candidate_rate:.3f} exceeds {ceiling:.3f} "
        f"(reference {reference_rate:.3f} x tolerance {ACCEPT_TOLERANCE})"
    )


# Tail past the p99 anchor (#3169): headroom is how much of [0, 1] is left
# above the p99->0.95 anchor, decay is set to match the p50->p99 segment's
# slope (0.75) at that anchor so the curve is continuous there.
_TAIL_HEADROOM = 1.0 - 0.95
# Slope-matched to the linear branch at frac=1 (d/dfrac of 0.2 + frac*0.75
# is 0.75), not fitted to live traffic -- #3169 review flagged this as an
# honest-measurement gap. Closing it needs a post-deploy field pass: count
# the fraction of alerts landing at score >= 0.999 over a real window, then
# re-derive this constant so that population lands <=20% at the observed
# p99 tail (tracked as a follow-up issue, not done here).
_TAIL_DECAY = 0.75 / _TAIL_HEADROOM


def _percentile_normalize(raw: float, p50: float, p99: float, lower_is_more_anomalous: bool) -> float:
    """Map a raw model score to [0, 1] using THIS model's own observed p50
    (typical/unremarkable) and p99 (near the top of what its own fit
    actually produced) as anchors, instead of a fixed linear formula that
    assumes a hand-picked "typical range" (#174).

    Found live: IsolationForest.score_samples() commonly ran ~-0.48 for
    real production traffic, nowhere near the old formula's assumed
    center of 0 -- and HBOS.decision_function() commonly ran 26-32, while
    the old formula divided by 10 and clipped, so every real score
    saturated at the ceiling (100% of a 4000-event live sample). Anchoring
    to p50/p99 computed fresh from each retrain's own holdout data means
    this can't go stale the way a hand-picked constant did: it recalibrates
    every retrain to whatever that fit actually produced.

    p50 maps to 0.2 (typical, unremarkable -- half of everything is
    literally this ordinary), p99 maps to 0.95 (only the top 1% of this
    model's OWN fit gets this high, consistent with CONTAMINATION=0.01).

    p99 is one order statistic from a small, recent holdout slice, not a
    census of the live stream it calibrates until the next retrain -- real
    traffic routinely runs a bit past it. #3169: extrapolating past p99 at
    the SAME slope as the p50->p99 segment meant only ~6.5% of that
    segment's own length beyond the anchor was enough to clip to exactly
    1.0, pinning 52.4% of live alerts to one indistinguishable ceiling
    value. Past p99 this now decays toward 1.0 instead, with the decay
    rate picked so the curve is continuous and slope-matched at the p99
    anchor (frac=1): still asymptotes to 1.0 for genuinely extreme scores,
    but takes meaningfully more than a noisy anchor's own margin of error
    to get there.
    """
    if p99 == p50:
        return 0.5
    frac = (p50 - raw) / (p50 - p99) if lower_is_more_anomalous else (raw - p50) / (p99 - p50)
    if frac <= 1.0:
        return float(np.clip(0.2 + frac * 0.75, 0.0, 1.0))
    return float(1.0 - _TAIL_HEADROOM * math.exp(-_TAIL_DECAY * (frac - 1.0)))


def _percentile_normalize_batch(raw: np.ndarray, p50: float, p99: float, lower_is_more_anomalous: bool) -> np.ndarray:
    """Array form of _percentile_normalize() -- identical anchors and
    formula, vectorized over a whole batch of raw scores instead of one at
    a time. Used by score_batch()/hbos_score_batch() (#1227)."""
    if p99 == p50:
        return np.full_like(raw, 0.5, dtype=float)
    frac = (p50 - raw) / (p50 - p99) if lower_is_more_anomalous else (raw - p50) / (p99 - p50)
    linear = np.clip(0.2 + frac * 0.75, 0.0, 1.0)
    # np.where evaluates both branches over the whole array first, so a
    # very negative frac (deep below p50) would overflow exp() here even
    # though np.where discards that element -- clamp the exponent's input
    # to >=0 so the discarded branch never computes an overflowing value.
    tail = 1.0 - _TAIL_HEADROOM * np.exp(-_TAIL_DECAY * np.maximum(frac - 1.0, 0.0))
    return np.where(frac <= 1.0, linear, tail)


def _anomaly_rate(iso: IsolationForest, hbos: HBOS, X: np.ndarray) -> float:
    """Fraction of X either model's OWN contamination-driven decision
    boundary calls anomalous -- IsolationForest.predict()==-1,
    HBOS.predict()==1 -- not an externally chosen score cutoff, so this rate
    reflects what each model actually learned rather than an arbitrary
    threshold picked to make the comparison come out a certain way."""
    if len(X) == 0:
        return 0.0
    iso_flag = iso.predict(X) == -1
    hbos_flag = hbos.predict(X) == 1
    return float(np.logical_or(iso_flag, hbos_flag).mean())


class IsoForestModel:
    """
    Wraps IsolationForest + HBOS.
    Both are fitted on the first retrain() call.
    Before first training, score()/hbos_score() return None -- not a
    neutral 0.5 (#1969): an untrained model has no calibration data and
    therefore no opinion, and a placeholder that kept its full composite
    weight was indistinguishable from a real middling vote (#1959 measured
    exactly that: mean IsoForest contribution 0.5000 across 6,669 alerts
    during a day the detector had never been trained). The caller's
    compute_composite() renormalises over the detectors that did produce
    an opinion.
    """

    def __init__(self, model_dir: str = "/models") -> None:
        self.model_dir  = model_dir
        self.iso: Optional[IsolationForest] = None
        self.hbos: Optional[HBOS] = None
        self._load_latest()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def extract_features(self, src: dict, cmd_count: int = 0,
                          failed_logins_1h: int = 0, unique_ports_1h: int = 1,
                          payload_bytes: bytes = b"") -> np.ndarray:
        """Convert a real honeypot-v2-*/suricata-v2-* ES _source dict to a
        feature vector. See the module-level _get_* helpers and
        docs/ml-worker-plan.md §5.3 for exactly where each value is read
        from per sensor.

        cmd_count/failed_logins_1h/unique_ports_1h are now real (#277) --
        the caller supplies them, computed once per batch by
        models.session_features.SessionFeatureTracker (the live/online
        path, worker.py's score_and_write_events()) or
        compute_batch_session_features() (retrain()'s historical batches).
        This mirrors featurise_temporal()'s inter_arrival_s contract in
        models/lstm_autoencoder.py: the stateful bookkeeping (per-session
        counters, rolling 1h windows) lives with the caller, not inside this
        otherwise-pure function. Defaults (0/0/1) are the pre-#277 neutral
        values, kept only so a caller that genuinely has no session/window
        context (most direct unit tests) doesn't have to fabricate one.

        payload_hex remains unwired -- no sensor in this stack's real
        ingest pipeline emits a consistent raw-payload byte field (#277
        remaining scope; see docs/ml-worker-plan.md §5.3).
        """
        ts   = src.get("@timestamp") or src.get("timestamp")
        ip   = _get_ip(src)
        port = _get_port(src)

        username  = _get_username(src)
        password  = _get_password(src)
        duration  = _get_duration(src)

        features = np.array([
            _ts_to_hour(ts),                       # 0
            _ts_to_dow(ts),                        # 1
            min(port, 65535) / 65535.0,            # 2  normalised port
            _proto_enc(_get_transport_proto(src)), # 3
            min(duration, 3600) / 3600.0,          # 4  session duration
            min(cmd_count, MAX_CMD_COUNT) / MAX_CMD_COUNT, # 5
            _shannon_entropy(payload_bytes) / 8.0, # 6  payload entropy
            min(len(payload_bytes), 65535) / 65535.0, # 7 payload len
            min(len(username), 128) / 128.0,       # 8
            _str_entropy(password) / 8.0,          # 9
            min(failed_logins_1h, 500) / 500.0,    # 10 failed logins rolling
            min(unique_ports_1h, 65535) / 65535.0, # 11 port scan width
            _is_known_scanner(ip),                 # 12 bool
            0.0,                                   # 13 reserved: is_tor_exit
            0.0,                                   # 14 reserved: is_vpn
        ], dtype=np.float32)

        return features.reshape(1, -1)

    def score(self, features: np.ndarray) -> "float | None":
        """Return anomaly score in [0, 1] (1 = most anomalous), or None
        before the first accepted fit (#1969 -- no calibration data, no
        opinion)."""
        if self.iso is None:
            return None
        # sklearn IsoForest: score_samples returns negative scores;
        # more negative = more anomalous.
        raw = self.iso.score_samples(features)[0]
        calib = getattr(self.iso, "hp_calib", None)
        if calib is not None:
            return _percentile_normalize(raw, calib["p50"], calib["p99"], lower_is_more_anomalous=True)
        # Fallback for a model saved before #174 (no calibration attached
        # yet) -- the original fixed-range formula, kept only so an
        # in-flight model isn't left with no score() at all until its next
        # retrain recalibrates it.
        return float(np.clip((-raw) * 2, 0.0, 1.0))

    def hbos_score(self, features: np.ndarray) -> "float | None":
        """Return HBOS outlier score normalised to [0, 1], or None before
        the first accepted fit (#1969 -- see score())."""
        if self.hbos is None:
            return None
        raw = self.hbos.decision_function(features)[0]
        calib = getattr(self.hbos, "hp_calib", None)
        if calib is not None:
            # pyod convention: higher decision_function = more anomalous
            # (opposite of sklearn's IsolationForest).
            return _percentile_normalize(raw, calib["p50"], calib["p99"], lower_is_more_anomalous=False)
        # Fallback for a model saved before #174 -- see score()'s comment.
        return float(np.clip(raw / 10.0, 0.0, 1.0))

    def score_batch(self, features: np.ndarray) -> "np.ndarray | None":
        """Batched form of score(): one score_samples() call over the whole
        (n_events, n_features) matrix instead of one call per row.
        Returns None before the first accepted fit (#1969), same contract
        as score().

        #1227: confirmed live (production model, 2000 real events) that the
        per-row call path -- score() invoked once per event, as
        score_and_write_events() used to do -- cost ~38ms/event, over 1000x
        more than the same work done in one batched score_samples() call
        (~0.02ms/event). This is the dominant cost in ml-worker's growing
        classification backlog (worker's own real combined throughput was
        ~25 events/sec against ~50/sec combined real ingest), not GPU/LSTM
        as the issue's own filer initially suspected -- LSTM only costs
        ~3ms/call and runs on roughly half of events. sklearn's tree
        traversal doesn't amortize its setup cost across single-row Python
        calls the way it does across one vectorized call; scores are
        numerically identical to calling score() in a loop (confirmed: max
        abs diff 0.0 over the same 2000-event sample).
        """
        if self.iso is None:
            return None
        raw = self.iso.score_samples(features)
        calib = getattr(self.iso, "hp_calib", None)
        if calib is not None:
            return _percentile_normalize_batch(raw, calib["p50"], calib["p99"], lower_is_more_anomalous=True)
        return np.clip((-raw) * 2, 0.0, 1.0)

    def hbos_score_batch(self, features: np.ndarray) -> "np.ndarray | None":
        """Batched form of hbos_score() -- see score_batch()'s own comment
        for why this exists and the measured speedup. Returns None before
        the first accepted fit (#1969), same contract as score()."""
        if self.hbos is None:
            return None
        raw = self.hbos.decision_function(features)
        calib = getattr(self.hbos, "hp_calib", None)
        if calib is not None:
            return _percentile_normalize_batch(raw, calib["p50"], calib["p99"], lower_is_more_anomalous=False)
        return np.clip(raw / 10.0, 0.0, 1.0)

    def explain(self, features: np.ndarray, scores: dict) -> str:
        """Generate a human-readable explanation of the anomaly."""
        f = features.flatten()
        parts = []

        if f[11] > 0.01:
            n_ports = int(f[11] * 65535)
            parts.append(f"Port scan: {n_ports} unique ports in last hour")
        if f[6] > 0.6:
            parts.append(f"High payload entropy ({f[6]*8:.1f} bits — possible encryption/packing)")
        if f[10] > 0.1:
            n_fail = int(f[10] * 500)
            parts.append(f"Brute-force: {n_fail} failed logins in last hour")
        if f[12] == 1.0:
            parts.append("Source matches known scanner ASN (Shodan/Censys)")
        if f[4] < 0.005 and f[5] > 0.01:
            parts.append("Very short session with commands (automated exploit attempt)")
        # None-safe read (#1969): an absent LSTM score is a None in scores,
        # not a low one, and must neither crash this nor read as a high one.
        if (scores.get("lstm_ae") or 0) > 0.85:
            parts.append("Unusual temporal sequence vs. learned baseline (LSTM-AE)")

        if not parts:
            parts.append(f"Statistical outlier (composite score {scores.get('isolation_forest', 0):.2f})")

        return ". ".join(parts) + "."

    def retrain(self, sources: list, source_index_counts: Optional[dict] = None) -> RetrainResult:
        """Retrain candidate IsoForest/HBOS models and gate promotion on the
        acceptance bar (#65, docs/ml-worker-plan.md §11.1) -- fit on a train
        split, evaluate label-free on a holdout split never trained on, and
        only replace the currently active model if the candidate's holdout
        anomaly rate stays within ACCEPT_TOLERANCE of the outgoing model's
        (or CONTAMINATION, if this is the first-ever retrain). A rejected
        candidate is discarded; the active model keeps serving.

        Capped at MAX_TRAIN_SAMPLES regardless of how many sources the
        caller collected -- see the constant's comment for the cost
        rationale. #3097: the caller (worker.py) now fetches an already
        time-stratified, per-index-quota'd sample, so this is a defense-in-
        depth truncation only -- it takes the head of the list, not the
        tail, so it no longer systematically drops whichever index the
        caller happened to concatenate last.

        source_index_counts, if given, is the caller's per-index sample
        count (e.g. {"zeek-v1-conn-*": 6000, ...}) -- recorded verbatim into
        the accepted version's metadata (#3097 PR-1 step 4) alongside the
        distinct @timestamp hours actually present in `sources`, so a
        skewed training slice is visible in *.meta.json without re-deriving
        it from HBOS bin edges.

        cmd_count/failed_logins_1h/unique_ports_1h (#277) are computed once
        here via compute_batch_session_features() -- a pure, batch-local
        pass over exactly this capped set of sources, deliberately not
        shared with the live SessionFeatureTracker (see that module's own
        docstring for why a historical retrain batch and "live so far"
        state answer different questions).
        """
        if len(sources) > MAX_TRAIN_SAMPLES:
            sources = sources[:MAX_TRAIN_SAMPLES]

        train_hours = sorted({_ts_to_hour(s.get("@timestamp") or s.get("timestamp")) for s in sources})

        n = len(sources)
        if n < 2:
            return RetrainResult(
                accepted=False, reason="not enough data to retrain",
                train_samples=n, holdout_samples=0,
                anomaly_rate_new=0.0, anomaly_rate_previous=None,
                train_index_counts=source_index_counts, train_hours=train_hours,
            )

        # Local import: models.session_features imports _get_ip/_get_port
        # from this module, so importing it at module scope here would be
        # circular.
        from models.session_features import compute_batch_session_features
        batch_features = compute_batch_session_features(sources)

        # Holdout is the newest slice -- never trained on, evaluated after
        # fitting. sources are the caller's fetch order (worker.py sorts
        # ascending by @timestamp), so this is the most-recent-events split,
        # not a random one.
        holdout_n = min(max(HOLDOUT_MIN, int(n * HOLDOUT_FRACTION)), n - 1)
        train_sources, train_features = sources[:n - holdout_n], batch_features[:n - holdout_n]
        holdout_sources, holdout_features = sources[n - holdout_n:], batch_features[n - holdout_n:]

        X_train = np.vstack([
            self.extract_features(s, **f) for s, f in zip(train_sources, train_features)
        ]).reshape(len(train_sources), N_FEATURES)
        X_holdout = np.vstack([
            self.extract_features(s, **f) for s, f in zip(holdout_sources, holdout_features)
        ]).reshape(len(holdout_sources), N_FEATURES)

        candidate_iso = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=N_JOBS,
        )
        candidate_hbos = HBOS(contamination=CONTAMINATION)
        try:
            candidate_iso.fit(X_train)
            candidate_hbos.fit(X_train)
            candidate_rate = _anomaly_rate(candidate_iso, candidate_hbos, X_holdout)
            if not np.isfinite(candidate_rate):
                raise ValueError(f"non-finite anomaly rate: {candidate_rate}")
            # #174: calibration anchors travel with the fitted model object
            # itself (joblib.dump/load preserve arbitrary extra attributes,
            # not just sklearn/pyod's own) -- computed from THIS retrain's
            # own holdout, so score()/hbos_score() recalibrate every retrain
            # instead of trusting a constant that can go stale.
            if len(X_holdout) > 0:
                iso_raw_holdout = candidate_iso.score_samples(X_holdout)
                hbos_raw_holdout = candidate_hbos.decision_function(X_holdout)
                iso_p50 = float(np.percentile(iso_raw_holdout, 50))
                # #3097: sklearn score_samples() is lower-is-more-anomalous, so
                # the anomalous tail is the 1st percentile, not the 99th --
                # np.percentile(..., 99) anchored on the most NORMAL 1% instead
                # (live: p50=-0.4133, "p99"=-0.3840, i.e. p99 > p50), which
                # made _percentile_normalize's frac denominator negative and
                # inverted every score since #174. Key stays "p99" (it's still
                # the tail anchor _percentile_normalize expects) -- only the
                # percentile it's computed from changes.
                iso_tail = float(np.percentile(iso_raw_holdout, 1))
                hbos_p50 = float(np.percentile(hbos_raw_holdout, 50))
                # pyod decision_function() is higher-is-more-anomalous, so its
                # tail anchor is correctly the 99th percentile -- unaffected by
                # the bug above, kept symmetric with the assertion below.
                hbos_tail = float(np.percentile(hbos_raw_holdout, 99))
                # Strict-only: equal anchors (e.g. a degenerate holdout where
                # every raw score ties) are a real but separate case, already
                # handled by _percentile_normalize's neutral-0.5 fallback --
                # not a sign inversion, so not a reject here.
                if iso_tail > iso_p50 or hbos_tail < hbos_p50:
                    return RetrainResult(
                        accepted=False,
                        reason=(f"tail anchor on wrong side of p50 for this detector's sign "
                                f"(iso tail={iso_tail:.4f} p50={iso_p50:.4f}, "
                                f"hbos tail={hbos_tail:.4f} p50={hbos_p50:.4f})"),
                        train_samples=len(train_sources), holdout_samples=len(holdout_sources),
                        anomaly_rate_new=0.0, anomaly_rate_previous=None,
                        train_index_counts=source_index_counts, train_hours=train_hours,
                    )
                candidate_iso.hp_calib = {"p50": iso_p50, "p99": iso_tail}
                candidate_hbos.hp_calib = {"p50": hbos_p50, "p99": hbos_tail}
        except Exception as exc:
            return RetrainResult(
                accepted=False, reason=f"candidate failed to fit or score holdout: {exc}",
                train_samples=len(train_sources), holdout_samples=len(holdout_sources),
                anomaly_rate_new=0.0, anomaly_rate_previous=None,
                train_index_counts=source_index_counts, train_hours=train_hours,
            )

        previous_rate = None
        if self.iso is not None and self.hbos is not None:
            previous_rate = _anomaly_rate(self.iso, self.hbos, X_holdout)

        accept, reason = _accept_decision(candidate_rate, previous_rate)
        result = RetrainResult(
            accepted=accept, reason=reason,
            train_samples=len(train_sources), holdout_samples=len(holdout_sources),
            anomaly_rate_new=candidate_rate, anomaly_rate_previous=previous_rate,
            train_index_counts=source_index_counts, train_hours=train_hours,
        )

        if accept:
            self.iso = candidate_iso
            self.hbos = candidate_hbos
            self._save(result)

        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self, result: RetrainResult) -> None:
        # #2230: detect a manually staged rollback BEFORE the new version's
        # files exist -- written-but-unpromoted, the new file would already
        # be "newest on disk", making a legitimately-staged pointer
        # indistinguishable from normal state. Dashboards surface retrains,
        # not symlink churn; without this line an operator's staged
        # rollback dies here invisibly.
        for prefix in ("isoforest", "hbos"):
            staged = staged_rollback_version(self.model_dir, prefix)
            if staged is not None:
                logger.warning(
                    f"{prefix}: accepted retrain overrides a manually staged rollback "
                    f"(live pointer was v{staged}); restart will load this NEW model -- "
                    f"re-run rollback.py {prefix} {staged} if the rollback was intended")

        ts = int(time.time())
        iso_path  = os.path.join(self.model_dir, f"isoforest_{ts}.joblib")
        hbos_path = os.path.join(self.model_dir, f"hbos_{ts}.joblib")
        os.makedirs(self.model_dir, exist_ok=True)
        joblib.dump(self.iso,  iso_path)
        joblib.dump(self.hbos, hbos_path)
        # Update symlinks
        _symlink(iso_path,  os.path.join(self.model_dir, "current_isoforest.joblib"))
        _symlink(hbos_path, os.path.join(self.model_dir, "current_hbos.joblib"))
        # Version metadata + retention (#65, docs/ml-worker-plan.md §11.3):
        # the evidence for why this version was promoted, kept next to the
        # model file itself so it survives independent of Elasticsearch
        # retention, and pruning back to MAX_RETAINED_VERSIONS so /models/
        # doesn't grow two files per model every RETRAIN_INTERVAL forever.
        meta = {"timestamp": ts, **asdict(result)}
        write_version_metadata(self.model_dir, "isoforest", ts, meta)
        write_version_metadata(self.model_dir, "hbos", ts, meta)
        prune_old_versions(self.model_dir, "isoforest")
        prune_old_versions(self.model_dir, "hbos")

    def _load_latest(self) -> None:
        iso_link  = os.path.join(self.model_dir, "current_isoforest.joblib")
        hbos_link = os.path.join(self.model_dir, "current_hbos.joblib")
        if os.path.exists(iso_link):
            self.iso  = joblib.load(iso_link)
        if os.path.exists(hbos_link):
            self.hbos = joblib.load(hbos_link)
