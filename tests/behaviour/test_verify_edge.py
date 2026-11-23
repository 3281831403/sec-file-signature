"""Behaviour tests for signature-bundle verification edge cases.

These five tests are immutable acceptance criteria; only
``signer/verify.py`` may change.
"""

import base64
import hashlib
import hmac

from signer.verify import (
    bundle_batch,
    verify_one,
    verify_threshold,
)

NOW = 1_800_000_000
DATA = b"release-payload:sec-file-signature:2026-11-19\n" + b"block-" * 512

CERT_A = "release-a"
CERT_B = "release-b"
SERIAL_A = "1001"
SERIAL_B = "1002"

KEY_A = b"release-key-a-v1"
KEY_B = b"release-key-b-v1"

GOOD_SIGNERS = (
    (CERT_A, SERIAL_A, KEY_A),
    (CERT_B, SERIAL_B, KEY_B),
)


def sign_digest(digest, key):
    """Reference signer: base64 HMAC-SHA256 over the raw digest bytes."""
    tag = hmac.new(key, bytes.fromhex(digest), hashlib.sha256).digest()
    return base64.b64encode(tag).decode("ascii")


def make_bundle(
    data=DATA,
    signers=GOOD_SIGNERS,
    issued_at=NOW - 30,
    expires_at=NOW + 600,
):
    """Build a correctly signed bundle for ``data`` without calling stubs."""
    digest = hashlib.sha256(data).hexdigest()
    return {
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


def make_policy(revoked=None):
    """Build a valid two-signer policy."""
    return {
        "threshold": 2,
        "check_revocation": True,
        "max_age": 900,
        "keys": {
            CERT_A: KEY_A,
            CERT_B: KEY_B,
        },
        "revoked": list(revoked or []),
    }


def test_single_signature_bundle_passes():
    bundle = make_bundle(signers=GOOD_SIGNERS[:1])
    signature = bundle["signatures"][0]

    assert verify_one(bundle["digest"], signature["signature"], KEY_A) is True
    assert verify_threshold(bundle, {CERT_A: KEY_A}, 1) is True


def test_threshold_met_passes_shortfall_rejects():
    keys = {CERT_A: KEY_A, CERT_B: KEY_B}

    two_signers = make_bundle(signers=GOOD_SIGNERS)
    assert verify_threshold(two_signers, keys, 2) is True

    one_signer = make_bundle(signers=GOOD_SIGNERS[:1])
    assert verify_threshold(one_signer, keys, 2) is False


def test_revoked_certificate_rejected():
    revoked = [
        {"name": CERT_A, "serial": SERIAL_A, "revoked_at": NOW - 100},
    ]
    bundle = make_bundle(
        signers=GOOD_SIGNERS,
        issued_at=NOW - 50,
        expires_at=NOW + 600,
    )

    result = bundle_batch(
        [{"bundle": bundle, "data": DATA}],
        make_policy(revoked=revoked),
        NOW,
    )

    assert result["results"] == [False]


def test_digest_mismatch_rejected():
    bundle = make_bundle(signers=GOOD_SIGNERS)
    policy = make_policy()

    accepted = bundle_batch(
        [{"bundle": bundle, "data": DATA}],
        policy,
        NOW,
    )
    assert accepted["results"] == [True]

    rejected = bundle_batch(
        [{"bundle": bundle, "data": DATA + b"tampered"}],
        policy,
        NOW,
    )
    assert rejected["results"] == [False]
    assert rejected["failed"] == 1


def test_two_batches_match_individual_checks():
    good = make_bundle(signers=GOOD_SIGNERS)
    bad_signature = make_bundle(
        signers=(
            (CERT_A, SERIAL_A, KEY_A),
            (CERT_B, SERIAL_B, b"attacker-key"),
        )
    )
    bad_digest = make_bundle(data=DATA, signers=GOOD_SIGNERS)

    units = [
        {"bundle": good, "data": DATA},
        {"bundle": bad_signature, "data": DATA},
        {"bundle": bad_digest, "data": DATA + b"injected"},
    ]
    policy = make_policy()

    first_batch = bundle_batch(units[:2], policy, NOW)
    second_batch = bundle_batch(units[2:], policy, NOW)
    individual = [
        bundle_batch([unit], policy, NOW)["results"][0] for unit in units
    ]

    assert first_batch["results"] + second_batch["results"] == individual
    assert individual == [True, False, False]
