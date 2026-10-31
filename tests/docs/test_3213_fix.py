#!/usr/bin/env python3
"""Regression tests for #3213: three credential questions, and no secret text.

The issue found that `http-honeypot` and `cisco-asa-honeypot` collapsed three
different things into one `password` field: whether a credential was present,
whether it could be parsed, and what the decoy's response meant. A request
whose body was too large to read looked identical to one that carried no
credential, and a 200 on a login page was indistinguishable from an
authentication that had actually succeeded.

The fix separates them (`credential_status`, `credential_present`,
`credential_indicator_match`, `auth_outcome`) and removes the secret itself --
not the field, the value: `body`, `query`, `data` and secret headers are
scrubbed too, because a removed field is not a removed leak.

What could quietly undo this, and is therefore asserted here rather than
assumed:

* **the twin files drifting apart.** The two sensors are separate Go modules
  with no dependency on each other, so `redaction.go` and `credentials.go`
  exist as deliberate byte-identical copies. That is exactly how a redaction
  bug is inherited: the fix lands in one module, the other keeps the old
  behaviour, and both look correct in review. Bugs found by running the built
  binaries and grepping their own emitted event streams, not by reading the
  code, are recorded here because each one is a shape a reviewer reads past:
  a field name truncated to `pass[redacted]`; a quoted JSON value bounded by
  the wrong separator so `{"password":"secret"}` leaked; a multipart part,
  whose value sits after a blank LINE and so had no separator for a
  key/value scan to act on; an HTML `name="password" value="..."` field,
  where another attribute sits between the name and the value; a form-typed
  body whose bytes are not a form, which was reported `absent` *and* stored
  verbatim; and `type="password"` read as a field name, which rewrote the
  following `name=` and walked the cursor past the real value.
* **a `password` field returning on the event**, in either module. It is
  absent from both structs today; nothing stops a later field from reintroducing
  it under a new name or an `omitempty` that a test would not notice.
* **`unknown` collapsing back into `absent`.** This is the issue's central
  distinction and the easiest to lose to a refactor that swaps a `*bool` for a
  `bool` because a nil check looked awkward.
* **an auth outcome derived from a status code.** `authReal` exists in both
  sensors and is unreachable; a future branch that sets it from `status == 200`
  would satisfy every vocabulary check in this file while reintroducing the
  exact inference the issue forbids.
* **a vendor default-credential list appearing on the ASA decoy.** A Cisco
  decoy makes `cisco123`-style bait the obvious thing to add, and it would be a
  claim about Cisco's products rather than about this fleet. The bait
  indicators are fictional and scoped to this fleet's own `nexusai-*` persona.
* **the proof being deleted rather than the bug being fixed.** Each headline
  test is named here, so removing one to make a suite green fails this file.

The `tests/docs/` CI row installs pytest and nothing else (see quality.yml), so
everything below is stdlib plus pytest, and the Go and Node suites are checked
as source rather than executed -- the two Go modules and the frontend each have
their own CI rows that run them for real.
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ARCANE = REPO_ROOT / "arcane/home"

HTTP = ARCANE / "honeypot-http/http-honeypot"
ASA = ARCANE / "honeypot-cisco-asa-honeypot/cisco-asa-honeypot"
BACKEND = ARCANE / "honeypot-dashboard/backend-service/src"
# The dashboard half (frontend-next credentialState.ts) left with #3749; its
# port to apiary-dashboard is Xore-Inc/apiary-dashboard#271.

# The two decoys this issue is about, and the only two the boundary covers.
SENSORS = {"http-honeypot": HTTP, "cisco-asa-honeypot": ASA}

# The credential-status vocabulary. Four, not the three the issue names: the
# parsed case cannot honestly be called any of them, and a fourth state that
# says "extracted" is more useful than an "extracted" that reads as
# "present but unparsed". `absent` and `unknown` are the pair the issue is
# about and must never be merged.
CREDENTIAL_STATES = {"absent", "present_unparsed", "extracted", "unknown"}
AUTH_OUTCOMES = {"simulated", "real", "unknown"}

# The canonical marker every layer must agree on. Three independent
# implementations (Go http, Go ASA, Rust) had to be taught the same value, and
# a reader comparing a freshly-captured body with a scrubbed one needs them to
# look the same.
MARKER = "[redacted]"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# ------------------------------------------------- the twin files stay twins ----


@pytest.mark.parametrize("name", ["redaction.go"])
def test_the_shared_scrubber_is_byte_identical_in_both_modules(name):
    """The two sensors cannot share a package, so this one is a deliberate copy.

    A copy that is edited on one side only is the failure mode this issue
    actually hit twice while it was being written: the bug is invisible in
    review on both sides, and the modules disagree about what a secret looks
    like. Asserting identity here is cheaper than re-discovering it in a
    credential sitting in an index.

    Only the scrubber is asserted byte-identical. `credentials.go` is a
    sibling rather than a copy -- it declares the same vocabulary but the ASA
    diverges where the ASA genuinely differs (its session signal, its form
    parser), and forcing those to match would be pretending the two decoys are
    the same decoy.
    """
    left = _read(HTTP / name)
    right = _read(ASA / name)
    assert left == right, (
        f"{name} has drifted between the two Go modules. They are independent "
        "modules with no shared package, so a divergence here means one "
        "sensor redactions differently from the other."
    )


def test_both_credentials_files_declare_the_same_vocabulary():
    """Same words, even though the files are not the same file.

    A state or outcome added on one side only is a vocabulary split: the API
    renders whatever string arrived, so the two decoys would answer the same
    question in different words and no test would notice.
    """
    left = _read(HTTP / "credentials.go")
    right = _read(ASA / "credentials.go")
    for state in CREDENTIAL_STATES:
        assert f'= "{state}"' in left and f'= "{state}"' in right, f"{state!r} is not declared in both"
    for outcome in AUTH_OUTCOMES:
        assert f'= "{outcome}"' in left and f'= "{outcome}"' in right, f"{outcome!r} is not declared in both"
    for tag in ('json:"credential_status"', 'json:"credential_present"',
                'json:"credential_indicator_match"', 'json:"auth_outcome"'):
        assert tag in _read(HTTP / "main.go") and tag in _read(ASA / "main.go")


def test_the_asa_says_where_it_deliberately_diverges():
    """A twin has to announce its differences, or the next reader assumes parity."""
    text = _read(ASA / "credentials.go")
    assert "twin" in text.lower()
    assert "http-honeypot/credentials.go" in text, "the ASA sibling should name the file it mirrors"


def test_the_shared_files_say_why_they_are_copies():
    """A future reader has to know this is load-bearing, not an accident."""
    head = _read(HTTP / "redaction.go")[:2000]
    assert "copy" in head.lower() or "twin" in head.lower() or "both" in head.lower()


# ------------------------------------------- the event carries no secret text ----


@pytest.mark.parametrize("sensor,root", sorted(SENSORS.items()))
def test_the_event_struct_has_no_password_field(sensor, root):
    """Removed, not blanked.

    A `password` key that is always empty is still a field a consumer can be
    told to read, and the issue's criteria are about what is emitted rather
    than about what is declined to fill in. Checked on the JSON tag rather than
    the Go field name so a rename cannot hide it.
    """
    main = _read(root / "main.go")
    struct = main[main.index("type event struct"):]
    struct = struct[: struct.index("\n}\n")]
    assert 'json:"password"' not in struct, f"{sensor}'s event still carries a password field"
    assert not re.search(r"\bPassword\b", struct), f"{sensor}'s event still has a Password member"


@pytest.mark.parametrize("sensor,root", sorted(SENSORS.items()))
def test_the_three_axes_are_present_and_typed_as_claimed(sensor, root):
    """`credential_present` must be a POINTER, not a bool.

    This is the whole issue in one type. A plain `bool` cannot represent
    "nobody knows", so an unreadable request reports `false` and becomes
    indistinguishable from a request that carried no credential.
    """
    main = _read(root / "main.go")
    struct = main[main.index("type event struct"):]
    struct = struct[: struct.index("\n}\n")]

    assert "CredentialStatus string `json:\"credential_status\"`" in struct
    assert "CredentialPresent *bool `json:\"credential_present\"`" in struct, (
        f"{sensor}: credential_present must be a *bool so unknown can be null"
    )
    assert "CredentialIndicatorMatch bool" in struct
    assert "AuthOutcome string `json:\"auth_outcome\"`" in struct
    # The account half is kept on purpose: a spray is a spray of accounts, and
    # a username is not a secret. Matched on the tag, not the whole line, so
    # `omitempty` is allowed.
    assert re.search(r"Username\s+string\s+`json:\"username", struct), (
        f"{sensor}: the account half is the analytic value and must stay on the event"
    )


@pytest.mark.parametrize("sensor,root", sorted(SENSORS.items()))
def test_the_declared_vocabulary_is_the_one_the_api_documents(sensor, root):
    """A state added in one module and not the other is a vocabulary split."""
    creds = _read(root / "credentials.go")
    for state in CREDENTIAL_STATES:
        assert f'= "{state}"' in creds, f"{sensor} does not declare credential state {state!r}"
    for outcome in AUTH_OUTCOMES:
        assert f'= "{outcome}"' in creds, f"{sensor} does not declare auth outcome {outcome!r}"


@pytest.mark.parametrize("sensor,root", sorted(SENSORS.items()))
def test_unknown_is_never_assigned_from_the_absent_state(sensor, root):
    """The collapse, checked at the source rather than in a test.

    `absent` and `unknown` both being "we found nothing" is the bug; the fix
    is that only a complete read of every channel may produce `absent`.
    """
    creds = _read(root / "credentials.go")
    # No line may set the status to the absent value as a side effect of a
    # failed or capped read.
    for line in creds.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        assert not re.search(r"=\s*credAbsent\b", stripped) or "==" in stripped or "!=" in stripped, (
            f"{sensor}: an assignment to the absent state is not an equality check: {stripped!r}"
        )
    assert "credUnknown" in creds


@pytest.mark.parametrize("sensor,root", sorted(SENSORS.items()))
def test_no_auth_outcome_is_derived_from_a_status_code(sensor, root):
    """`authReal` exists and is unreachable; that is the property.

    A branch that sets an auth outcome from `status == 200` would pass every
    vocabulary assertion in this file and reintroduce the exact inference the
    issue forbids, so the shape is asserted directly: no assignment to an auth
    outcome may mention a status.
    """
    for name in ("credentials.go", "main.go", "webvpn.go"):
        path = root / name
        if not path.exists():
            continue
        for n, line in enumerate(_read(path).splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            assigns_outcome = re.search(r"\.\s*authOutcome\s*=|authOutcome\s*=\s*auth|=\s*auth(Real|Simulated|Unknown)\b", stripped)
            if not assigns_outcome:
                continue
            assert "Status" not in stripped and "status" not in stripped, (
                f"{sensor}/{name}:{n} derives an auth outcome from a status: {stripped!r}"
            )


@pytest.mark.parametrize("sensor,root", sorted(SENSORS.items()))
def test_the_bait_indicators_are_not_a_vendor_default_list(sensor, root):
    """Fictional, and scoped to this fleet's own persona.

    A Cisco decoy makes a Cisco default-credential list the obvious thing to
    add, and it would be a claim about a real vendor's products. The bait is
    this fleet's own invented persona, and matching it means an ATTEMPT was
    made -- not that anything was accessed.
    """
    creds = _read(root / "credentials.go")
    for vendor in ("cisco123", "Cisco123", "cisco", "admin/cisco", "asa/", "fmc"):
        assert vendor not in creds, (
            f"{sensor}: {vendor!r} looks like a vendor default-credential claim rather than "
            "this fleet's own fictional bait"
        )
    assert "nexusai" in creds.lower(), "the bait indicators should be scoped to this fleet's persona"


# ------------------------------------------------- the secret is scrubbed ----


@pytest.mark.parametrize("sensor,root", sorted(SENSORS.items()))
def test_redaction_is_applied_to_every_channel_not_just_the_field(sensor, root):
    """Removing the field is not removing the leak.

    The pre-#3213 event put the submitted form in `body` (and the ASA's in
    `data`) and the query string in `query`, so a sensor that dropped only the
    `password` key would still have published every secret it ever saw.
    """
    creds = _read(root / "credentials.go")
    for channel in ("redactedBody", "redactedQuery", "redactSecretValues", "redactSecretHeaders"):
        assert channel in creds, f"{sensor} does not scrub via {channel}"


def test_all_three_implementations_agree_on_the_marker():
    """A reader comparing a fresh capture with a scrubbed one needs one word."""
    assert f'= "{MARKER}"' in _read(HTTP / "credentials.go") or MARKER in _read(HTTP / "redaction.go")
    assert f'MARKER: &str = "{MARKER}"' in _read(BACKEND / "secrets_boundary.rs")


# ------------------------------------------- the API does not serve it back ----


def test_the_api_boundary_covers_the_read_sites():
    """One choke point per entry point, and the files that read a credential.

    `honeypot.password` is read in several files. Each one that can reach a
    boundary sensor's document has to route through `secrets_boundary`
    instead, because Elasticsearch keeps every document it was ever given --
    redacting at the sensor fixes tomorrow's events and does nothing for the
    ones already indexed, which are the ones an analyst opens.
    """
    required = {
        "event_detail.rs": "detail_for",
        "event_page.rs": "scrub_source",
        "events.rs": "scrub_source",
        "sensors.rs": "scrub_event",
        "session.rs": "scrub_event",
    }
    for filename, symbol in required.items():
        text = _read(BACKEND / filename)
        assert "secrets_boundary" in text, f"{filename} never mentions the boundary"
        assert symbol in text, f"{filename} should reach the boundary through {symbol}"


def test_the_event_page_scrubs_the_raw_record_passthrough():
    """`record` is the document AS STORED, and the page's sharpest edge.

    Every derived field is guarded, and a page that returns the whole
    unscrubbed `_source` beside them hands over everything the guards removed.
    """
    page = _read(BACKEND / "event_page.rs")
    assert "secrets_boundary::scrub_source(&sensor, &source)" in page
    assert "record: record," in page or "record," in page, "the scrubbed value is what the field is built from"


def test_the_http_request_response_no_longer_offers_a_password_field():
    """Removed from the API too, not only from the event."""
    sensors = _read(BACKEND / "sensors.rs")
    struct = sensors[sensors.index("pub struct HttpRequest"):]
    struct = struct[: struct.index("\n}\n")]
    assert "pub password: String" not in struct
    assert "pub credential_status: String" in struct
    assert "pub credential_present: Option<bool>" in struct, (
        "credential_present must stay an Option so unknown is null on the wire"
    )


def test_the_boundary_is_scoped_to_the_two_sensors_in_this_issue():
    """Narrow on purpose, and the narrowing has to stay visible.

    cowrie, tanner, multipot and the rest still return their passwords. That
    is the remaining exposure the PR declares rather than hides; quietly
    changing ten sensors inside a fix for two would be a much larger breaking
    change than the one this already documents.
    """
    boundary = _read(BACKEND / "secrets_boundary.rs")
    match = re.search(r"pub const CREDENTIAL_SENSORS: &\[&str\] = &\[(.*?)\];", boundary, re.S)
    assert match, "the sensor scope is no longer a single named list"
    names = set(re.findall(r'"([^"]+)"', match.group(1)))
    assert names == set(SENSORS), f"the boundary's scope changed to {sorted(names)}"


def test_the_envelope_allowlist_is_not_reachable_from_attacker_data():
    """The allowlist that protects the axis fields must be envelope-only.

    `credential` and `auth` are both substrings of the axis field names, so
    the scrubber needs an exemption for them -- and an exemption honoured at
    any depth is a bypass: POST a field called `auth_type` and its value walks
    straight through. The depth has to be carried, not inferred.
    """
    boundary = _read(BACKEND / "secrets_boundary.rs")
    assert "depth == 0" in boundary, "the envelope exemption is no longer depth-guarded"
    assert "fn scrub_nested(node: &mut Map<String, Value>, depth: usize)" in boundary


def test_the_password_aggregation_cannot_be_asked_for_over_the_api():
    """An aggregation bucket key is assembled by Elasticsearch, not by us.

    The overview and attacker-profile panels used to be `multi_terms` over
    (username, password), so the top passwords in the fleet were returned in
    the response. Nothing downstream can scrub a bucket key -- it never
    passes through a document -- so the field must not be requested at all.
    """
    for filename in ("dashboard.rs", "investigate.rs"):
        text = _read(BACKEND / filename)
        assert "honeypot.password" not in text, (
            f"{filename} still asks Elasticsearch to aggregate honeypot.password; "
            "a bucket key carrying a secret cannot be scrubbed on the way out"
        )
        assert "honeypot.username" in text, f"{filename} should still aggregate the account"


# ------------------------------------------------------ the proof is intact ----


def test_the_headline_go_tests_are_still_here():
    """Deleting the proof is the one way to make this suite green for free."""
    expected = {
        HTTP: [
            "TestPasswordNeverReachesTheEvent",
            "TestEventHasNoPasswordField",
            "TestUnknownIsNeverCollapsedIntoAbsent",
            "TestAuthRealIsUnreachable",
            "TestAuthOutcomeIsNeverDerivedFromStatus",
            "TestAMultipartLoginPostIsScrubbed",
            "TestAMultipartBoundaryIsCaseSensitive",
            "TestAnHTMLFormFieldIsScrubbed",
            "TestAContentTypeThatLiesIsNotBelieved",
        ],
        ASA: [
            "TestPasswordNeverReachesTheEvent",
            "TestCredentialStatusStatesAreReachable",
            "TestUnknownIsNeverCollapsedIntoAbsent",
            "TestAuthRealIsUnreachable",
            "TestTheLoginFailurePageIsNotAnAuthSuccess",
            "TestNoSessionIdWasInvented",
            "TestCVEPayloadSurvivesRedaction",
            "TestAMultipartLogonPostIsScrubbedOnTheASA",
            "TestAnHTMLFormFieldIsScrubbedOnTheASA",
            "TestAContentTypeThatLiesIsNotBelievedOnTheASA",
        ],
    }
    for root, names in expected.items():
        text = _read(root / "credentials_test.go")
        for name in names:
            assert f"func {name}(" in text, f"{root.name} no longer has {name}"


def test_the_boundary_tests_are_still_here():
    for path, names in {
        BACKEND / "secrets_boundary.rs": [
            "fn the_axis_fields_survive_their_own_key_list",
            "fn the_envelope_allowlist_is_not_a_bypass",
            "fn the_password_field_is_removed_not_blanked",
        ],
    }.items():
        text = _read(path)
        for name in names:
            assert name in text, f"{path.name} no longer asserts {name!r}"


def test_the_api_response_tests_exist_on_both_sides_of_the_boundary():
    """The sensor proves it for the event; the API proves it for the response."""
    for filename, name in {
        "events.rs": "fn a_stored_password_never_reaches_an_event_row",
        "sensors.rs": "fn a_stored_password_never_reaches_the_http_request_response",
    }.items():
        assert name in _read(BACKEND / filename), f"{filename} no longer has {name}"
