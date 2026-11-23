"""Contract tests for signature-bundle verification.

These ten tests map one-for-one onto the ten defects in the exercise.  They
are immutable acceptance criteria; only ``signer/verify.py`` may change.
"""

import base64
import hashlib
import hmac
import json

from signer.verify import (
    bundle_batch,
    check_revocation,
    check_timestamp,
    digest_file,
    parse_bundle,
    validate_policy,
    verify_threshold,
)

NOW = 1_800_000_000
DATA = b"release-payload:sec-file-signature:2026-11-19\n" + b"block-" * 512

CERT_A = "release-a"
CERT_B = "release-b"
CERT_C = "release-c"
SERIAL_A = "1001"
SERIAL_B = "1002"
SERIAL_C = "1003"

KEY_A = b"release-key-a-v1"
KEY_B = b"release-key-b-v1"
KEY_C = b"release-key-c-v1"

GOOD_SIGNERS = (
    (CERT_A, SERIAL_A, KEY_A),
    (CERT_B, SERIAL_B, KEY_B),
)


def sign_digest(digest, key):
    """Reference signer: base64 HMAC-SHA256 over the raw digest bytes."""
    message = bytes.fromhex(digest)
    tag = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(tag).decode("ascii")


def make_bundle(
    data=DATA,
    signers=GOOD_SIGNERS,
    issued_at=NOW - 30,
    expires_at=NOW + 600,
    extra=None,
):
    """Build a correctly signed bundle for ``data`` without calling stubs."""
    digest = hashlib.sha256(data).hexdigest()
    bundle = {
        "digest": digest,
        "signatures": [
            {
                "cert_id": cert_id,
                "serial": serial,
                "signature": sign_digest(digest, key),
            }
            for cert_id, serial, key in signers
        ],
        "timestamp": {"issued_at": issued_at, "expires_at": expires_at},
    }
    if extra:
        bundle.update(extra)
    return bundle


def make_policy(threshold=2, revoked=None):
    """Build a policy with a trustworthy multi-signature threshold."""
    return {
        "threshold": threshold,
        "check_revocation": True,
        "max_age": 900,
        "keys": {
            CERT_A: KEY_A,
            CERT_B: KEY_B,
            CERT_C: KEY_C,
        },
        "revoked": list(revoked or []),
    }


# Defect 1: a digest of only the first bytes misses tampering in the tail.
def test_digest_covers_tail_bytes():
    prefix = b"header:" + b"\x00" * 4096
    tail = b"original-tail"
    tampered = b"tampered-tail"

    assert digest_file([prefix, tail]) == hashlib.sha256(prefix + tail).hexdigest()
    assert digest_file([prefix, tampered]) == hashlib.sha256(
        prefix + tampered
    ).hexdigest()
    assert digest_file([prefix, tail]) != digest_file([prefix, tampered])


# Defect 2: parsing keeps only the first signature and ignores the rest.
def test_parse_bundle_preserves_all_signatures():
    signers = GOOD_SIGNERS + ((CERT_C, SERIAL_C, KEY_C),)
    bundle = make_bundle(signers=signers)
    parsed = parse_bundle(json.dumps(bundle, sort_keys=True))

    assert [item["cert_id"] for item in parsed["signatures"]] == [
        CERT_A,
        CERT_B,
        CERT_C,
    ]
    assert [item["serial"] for item in parsed["signatures"]] == [
        SERIAL_A,
        SERIAL_B,
        SERIAL_C,
    ]
    assert [item["signature"] for item in parsed["signatures"]] == [
        item["signature"] for item in bundle["signatures"]
    ]
    assert parsed["digest"] == bundle["digest"]


# Defect 3: summing signatures lets duplicate entries fake a threshold.
def test_threshold_rejects_duplicate_signature_inflation():
    bundle = make_bundle(signers=GOOD_SIGNERS[:1])
    duplicated = dict(bundle["signatures"][0])
    bundle["signatures"] = [bundle["signatures"][0], duplicated]

    assert verify_threshold(bundle, {CERT_A: KEY_A}, 2) is False


# Defect 4: taking the threshold from the bundle lets an attacker set it to 1.
def test_threshold_comes_from_argument_not_bundle():
    bundle = make_bundle(signers=GOOD_SIGNERS[:1], extra={"threshold": 1})

    assert bundle["threshold"] == 1
    assert verify_threshold(bundle, {CERT_A: KEY_A}, 2) is False


# Defect 5: revocation compares only the certificate name, not its serial.
def test_revocation_checks_serial_not_only_name():
    revoked = [
        {"name": CERT_A, "serial": "9999", "revoked_at": NOW - 100},
    ]
    assert check_revocation((CERT_A, SERIAL_A), revoked, NOW) is True

    revoked.append(
        {"name": CERT_A, "serial": SERIAL_A, "revoked_at": NOW - 100}
    )
    assert check_revocation((CERT_A, SERIAL_A), revoked, NOW) is False


# Defect 6: revocation ignores revoked_at and rejects pre-revocation signatures.
def test_revocation_respects_revocation_time():
    revoked = [{"name": CERT_A, "serial": SERIAL_A, "revoked_at": NOW}]

    assert check_revocation((CERT_A, SERIAL_A), revoked, NOW - 1) is True
    assert check_revocation((CERT_A, SERIAL_A), revoked, NOW) is False
    assert check_revocation((CERT_A, SERIAL_A), revoked, NOW + 1) is False


# Defect 7: timestamps are only ordered, so future times and old replays pass.
def test_timestamp_rejects_future_issue_and_replay():
    policy = {"max_age": 300}

    future = make_bundle(issued_at=NOW + 1, expires_at=NOW + 301)
    assert check_timestamp(future, NOW, policy) is False

    # Old bundle replay: expires_at is still in the future, but its age is not.
    replayed = make_bundle(issued_at=NOW - 301, expires_at=NOW + 300)
    assert check_timestamp(replayed, NOW, policy) is False

    boundary = make_bundle(issued_at=NOW - 300, expires_at=NOW)
    assert check_timestamp(boundary, NOW, policy) is True


# Defect 8: policy validation forgets to reject a threshold of one.
def test_policy_flags_threshold_one():
    weak = {"threshold": 1, "check_revocation": True, "max_age": 300}
    assert validate_policy(weak) == ["threshold_not_above_one"]

    empty = {}
    assert validate_policy(empty) == [
        "threshold_not_above_one",
        "revocation_not_checked",
        "time_window_not_limited",
    ]

    strong = {"threshold": 2, "check_revocation": True, "max_age": 300}
    assert validate_policy(strong) == []


# Defect 9: batch verification reuses the previous signature result.
def test_batch_rechecks_second_bundle():
    good = make_bundle(data=DATA, signers=GOOD_SIGNERS)
    bad = make_bundle(
        data=DATA,
        signers=(
            (CERT_A, SERIAL_A, KEY_A),
            (CERT_B, SERIAL_B, b"attacker-key"),
        ),
    )
    units = [
        {"bundle": good, "data": DATA},
        {"bundle": bad, "data": DATA},
    ]

    result = bundle_batch(units, make_policy(), NOW)

    assert result["results"] == [True, False]
    assert result["passed"] == 1
    assert result["failed"] == 1


# Defect 10: the bundle digest is never compared with the actual file digest.
def test_batch_rejects_digest_mismatch():
    signed_data = b"genuine-release-artifact"
    actual_data = b"genuine-release-artifact-with-injected-bytes"
    bundle = make_bundle(data=signed_data, signers=GOOD_SIGNERS)

    result = bundle_batch(
        [{"bundle": bundle, "data": actual_data}],
        make_policy(),
        NOW,
    )

    assert result["results"] == [False]
    assert result["passed"] == 0
