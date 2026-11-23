"""Signature-bundle verification: executable specification with eight stubs.

A signature bundle is a mapping, or a JSON document containing one object::

    {
        "digest": "<64 lowercase hex characters: SHA-256 of the whole file>",
        "signatures": [
            {
                "cert_id": "<signer identity>",
                "serial": "<certificate serial number as a string>",
                "signature": "<base64 of HMAC-SHA256(key, bytes.fromhex(digest))>",
            },
            ...
        ],
        "timestamp": {"issued_at": <int>, "expires_at": <int>},
    }

A bundle may also contain other keys, including a package-supplied
``threshold``.  That package-supplied value is untrusted; the verifier only
ever uses the threshold supplied by its policy or caller.

A policy is a mapping::

    {
        "threshold": int,              # trusted minimum distinct signers, > 1
        "check_revocation": bool,      # must be the literal value True
        "max_age": int,                # trusted timestamp age limit in seconds
        "keys": {cert_id: bytes},      # trusted HMAC keys
        "revoked": [                   # trusted revocation list
            {"name": str, "serial": str, "revoked_at": int},
            ...
        ],
    }

The HMAC message is the raw bytes represented by the lowercase hex digest,
not the ASCII hex text.  All functions are deterministic, offline and use
only the standard library.  They must not mutate their arguments.  Ordinary
verification failures return False (or a False result for the offending
item); only parse_bundle reports a malformed bundle by raising ValueError.
All comparisons are exact: time, digest, serial and signature matching have
tolerance 0.
"""

import base64
import binascii
import hashlib
import hmac
import json

_HEX_DIGITS = frozenset("0123456789abcdef")


def _is_int(value) -> bool:
    """True for real integers; booleans are not accepted as integers."""
    return isinstance(value, int) and not isinstance(value, bool)


def digest_file(data) -> str:
    """Return the complete SHA-256 digest of a file as lowercase hex.

    ``data`` is a bytes-like object or an iterable of bytes-like chunks, such
    as the chunks streamed from a file.  Every byte is fed exactly once to
    ``hashlib.sha256`` in stream order.  The result must equal
    ``hashlib.sha256(b"".join(chunks)).hexdigest()`` for every input; neither
    a prefix nor a suffix may be dropped.  Streaming semantics are required:
    callers may pass a long chunk sequence, so do not slice the file to a
    fixed prefix and do not assume the first chunk is the whole file.

    A text string is not a file body and is rejected with TypeError.  The
    digest is lowercase hexadecimal so it can be compared exactly with the
    bundle digest.
    """
    if isinstance(data, str):
        raise TypeError("a text string is not a file body")
    if isinstance(data, (bytes, bytearray, memoryview)):
        chunks = (data,)
    else:
        chunks = data
    hasher = hashlib.sha256()
    for chunk in chunks:
        if isinstance(chunk, str):
            raise TypeError("a text string is not a file body")
        hasher.update(bytes(chunk))
    return hasher.hexdigest()


def parse_bundle(bundle) -> dict:
    """Parse a signature bundle and keep every signature.

    ``bundle`` is a mapping, a JSON ``str``, or UTF-8 JSON ``bytes``.
    Return a new dict.  Required keys are normalized as follows:

      * ``digest``: exactly 64 lowercase hexadecimal characters;
      * ``signatures``: a non-empty list preserving input order; each item is
        a new dict with non-empty string ``cert_id``, non-empty string
        ``serial``, and a valid base64 ``signature`` string;
      * ``timestamp``: a new dict with integer ``issued_at`` and integer
        ``expires_at`` (booleans are not accepted as integers).

    Unknown top-level keys, including an untrusted ``threshold``, are copied
    unchanged.  All signatures must be preserved: parsing must never discard
    every signature after the first one, because the threshold verifier needs
    the complete multi-signature list.

    Raise ValueError for malformed JSON, a non-object document, a missing or
    invalid required field, an invalid timestamp object, or a signature that
    is not valid base64.  Do not verify the signature here.
    """
    if isinstance(bundle, (str, bytes, bytearray)):
        try:
            document = json.loads(bundle)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("malformed JSON bundle") from exc
    elif isinstance(bundle, dict):
        document = bundle
    else:
        raise ValueError("bundle must be a mapping or JSON document")

    if not isinstance(document, dict):
        raise ValueError("bundle document must be a JSON object")

    digest = document.get("digest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in _HEX_DIGITS for char in digest)
    ):
        raise ValueError("digest must be 64 lowercase hexadecimal characters")

    signatures = document.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ValueError("signatures must be a non-empty list")
    parsed_signatures = []
    for entry in signatures:
        if not isinstance(entry, dict):
            raise ValueError("each signature entry must be an object")
        cert_id = entry.get("cert_id")
        serial = entry.get("serial")
        signature = entry.get("signature")
        if not isinstance(cert_id, str) or not cert_id:
            raise ValueError("cert_id must be a non-empty string")
        if not isinstance(serial, str) or not serial:
            raise ValueError("serial must be a non-empty string")
        if not isinstance(signature, str):
            raise ValueError("signature must be a base64 string")
        try:
            base64.b64decode(signature, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("signature is not valid base64") from exc
        parsed_signatures.append(
            {"cert_id": cert_id, "serial": serial, "signature": signature}
        )

    timestamp = document.get("timestamp")
    if not isinstance(timestamp, dict):
        raise ValueError("timestamp must be an object")
    issued_at = timestamp.get("issued_at")
    expires_at = timestamp.get("expires_at")
    if not _is_int(issued_at) or not _is_int(expires_at):
        raise ValueError("timestamp fields must be integers")

    parsed = dict(document)
    parsed["digest"] = digest
    parsed["signatures"] = parsed_signatures
    parsed["timestamp"] = {"issued_at": issued_at, "expires_at": expires_at}
    return parsed


def verify_one(digest, signature, key) -> bool:
    """Verify one HMAC-SHA256 signature in constant time.

    ``digest`` is a 64-character lowercase hex SHA-256 digest, ``signature``
    is the base64 text of the expected HMAC tag, and ``key`` is bytes.  The
    signed message is ``bytes.fromhex(digest)``.  Return True only when the
    decoded tag equals ``hmac.new(key, message, hashlib.sha256).digest()``.

    Use ``hmac.compare_digest`` on the raw tag bytes.  Do not use ``==`` and
    do not return early on a length mismatch or a malformed base64 value;
    any malformed digest, signature or key makes this one signature invalid
    and returns False rather than raising.  Tolerance is 0: no alternate key,
    truncated tag or non-canonical encoding is accepted.
    """
    try:
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in _HEX_DIGITS for char in digest)
        ):
            return False
        if not isinstance(signature, str):
            return False
        if not isinstance(key, (bytes, bytearray)):
            return False
        message = bytes.fromhex(digest)
        try:
            tag = base64.b64decode(signature, validate=True)
        except (binascii.Error, ValueError):
            return False
        expected = hmac.new(bytes(key), message, hashlib.sha256).digest()
        return hmac.compare_digest(tag, expected)
    except Exception:
        return False


def verify_threshold(bundle, keys, threshold) -> bool:
    """Return whether distinct valid signers reach the supplied threshold.

    ``bundle`` is a parsed bundle from parse_bundle, ``keys`` maps
    ``cert_id`` to bytes, and ``threshold`` is the trusted positive integer
    supplied by the caller.  Never read threshold from the bundle: an
    attacker can set a package field to 1.

    Verify each signature with verify_one against the key for its
    ``cert_id``.  Count each distinct ``cert_id`` at most once.  Duplicate
    signature entries, repeated serials and copied base64 values must not
    inflate the count; counting signatures by summing booleans is a bug.
    Missing keys and invalid signatures do not count.  Return True exactly
    when the number of distinct valid signers is at least ``threshold``.
    Threshold 1 is meaningful for this primitive, although validate_policy
    rejects it as too weak for a trusted policy.  This function does not
    check timestamps or revocation; bundle_batch composes those checks.
    """
    if not _is_int(threshold) or threshold < 1:
        return False
    if not isinstance(bundle, dict) or not isinstance(keys, dict):
        return False
    signatures = bundle.get("signatures")
    if not isinstance(signatures, list):
        return False
    digest = bundle.get("digest")
    valid_signers = set()
    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        cert_id = entry.get("cert_id")
        if not isinstance(cert_id, str) or cert_id in valid_signers:
            continue
        key = keys.get(cert_id)
        if key is None:
            continue
        if verify_one(digest, entry.get("signature"), key):
            valid_signers.add(cert_id)
    return len(valid_signers) >= threshold


def check_revocation(cert_id, revoked, now) -> bool:
    """Return True when a certificate is acceptable at time ``now``.

    ``cert_id`` is a pair ``(common_name, serial)``, both strings.  ``revoked``
    is the trusted revocation list; each record has ``name``, ``serial`` and
    integer ``revoked_at``.  A certificate is revoked only when both the name
    and the serial match a record, so a record for another serial number of
    the same CA or subject name must not reject this certificate.

    Time matters: a matching record is in force when ``revoked_at <= now``.
    A record whose revocation is later than ``now`` has not happened yet and
    does not reject the certificate.  Callers assessing a signature pass the
    bundle timestamp as ``now`` so a signature issued before revocation stays
    acceptable while one issued at or after revocation is rejected.  The
    boundary is inclusive and tolerance is 0.  Return False for a malformed
    cert_id or a malformed matching record; return True when no matching
    record is in force.
    """
    if (
        not isinstance(cert_id, (tuple, list))
        or len(cert_id) != 2
        or not isinstance(cert_id[0], str)
        or not isinstance(cert_id[1], str)
    ):
        return False
    if not _is_int(now):
        return False
    name, serial = cert_id
    for record in revoked or ():
        if not isinstance(record, dict):
            continue
        if record.get("name") != name or record.get("serial") != serial:
            continue
        revoked_at = record.get("revoked_at")
        if not _is_int(revoked_at):
            return False
        if revoked_at <= now:
            return False
    return True


def check_timestamp(bundle, now, policy) -> bool:
    """Return True when the bundle timestamp is fresh and ordered.

    ``bundle`` is a parsed bundle, ``now`` is an explicit integer supplied by
    the caller, and ``policy["max_age"]`` is a positive integer number of
    seconds.  There is no wall-clock fallback and no randomness.  The check
    requires all of the following:

      * ``issued_at`` and ``expires_at`` are integers and
        ``issued_at <= expires_at``;
      * ``issued_at <= now <= expires_at``, so a future issue time is invalid;
      * ``now - issued_at <= max_age``, so a stale timestamp is invalid.

    Both interval boundaries are inclusive.  A future issued_at is never
    given any grace, even by one second: tolerance is 0.  Return False for a
    missing or malformed timestamp, a non-positive max_age, or a failed
    bound instead of raising.
    """
    if not isinstance(bundle, dict) or not isinstance(policy, dict):
        return False
    if not _is_int(now):
        return False
    max_age = policy.get("max_age")
    if not _is_int(max_age) or max_age <= 0:
        return False
    timestamp = bundle.get("timestamp")
    if not isinstance(timestamp, dict):
        return False
    issued_at = timestamp.get("issued_at")
    expires_at = timestamp.get("expires_at")
    if not _is_int(issued_at) or not _is_int(expires_at):
        return False
    if issued_at > expires_at:
        return False
    if not (issued_at <= now <= expires_at):
        return False
    if now - issued_at > max_age:
        return False
    return True


def validate_policy(policy) -> list[str]:
    """Return the policy problems in a fixed, stable order.

    The result is a list of issue codes, one code per problem, in this exact
    order:

      * ``threshold_not_above_one`` when a trusted threshold is missing, is
        not an integer (booleans excluded), or is less than 2;
      * ``revocation_not_checked`` when check_revocation is not the literal
        value True;
      * ``time_window_not_limited`` when max_age is missing, is not an
        integer (booleans excluded), or is not positive.

    A valid policy returns an empty list.  Do not add other issue codes and
    do not stop after the first problem: the caller needs the complete list.
    In particular, threshold 1 must be reported, because a package cannot be
    allowed to weaken a multi-signature policy to a single signature.
    """
    issues = []
    get = policy.get if isinstance(policy, dict) else lambda key, default=None: default

    threshold = get("threshold")
    if not _is_int(threshold) or threshold < 2:
        issues.append("threshold_not_above_one")

    if get("check_revocation") is not True:
        issues.append("revocation_not_checked")

    max_age = get("max_age")
    if not _is_int(max_age) or max_age <= 0:
        issues.append("time_window_not_limited")

    return issues


def bundle_batch(bundles, policy, now) -> dict:
    """Verify independent file-and-bundle units and report each result.

    ``bundles`` is a sequence of mappings::

        {"bundle": <mapping or JSON text>, "data": <bytes or chunk iterable>}

    Each item is independent; no parsed bundle, digest, signature result or
    threshold may be reused for a later item.  For every item, check the
    complete file digest against the bundle digest with digest_file, check
    the timestamp with check_timestamp, reach the trusted policy threshold
    with verify_threshold using policy["keys"], and, when the policy enables
    revocation, check every signer with check_revocation at the bundle
    timestamp's ``issued_at`` (not at ``now``).  A package whose declared
    digest differs from the actual file must fail even when all signatures
    are cryptographically valid for the declared digest.

    A malformed item produces False for that item without aborting the rest.
    If validate_policy reports any issue, every item is rejected.  Return::

        {
            "results": [bool, ...],   # input order, one entry per item
            "passed": int,            # number of True entries
            "failed": int,            # number of False entries
        }

    ``passed + failed == len(bundles)``.  Do not mutate the inputs.
    """
    policy_ok = not validate_policy(policy)
    keys = policy.get("keys", {}) if isinstance(policy, dict) else {}
    revoked = policy.get("revoked", []) if isinstance(policy, dict) else []
    threshold = policy.get("threshold") if isinstance(policy, dict) else None
    revocation_enabled = (
        isinstance(policy, dict) and policy.get("check_revocation") is True
    )

    results = []
    for unit in bundles:
        ok = False
        if policy_ok:
            try:
                parsed = parse_bundle(unit["bundle"])
                actual_digest = digest_file(unit["data"])
                if actual_digest == parsed["digest"]:
                    if check_timestamp(parsed, now, policy):
                        if verify_threshold(parsed, keys, threshold):
                            if revocation_enabled:
                                issued_at = parsed["timestamp"]["issued_at"]
                                ok = all(
                                    check_revocation(
                                        (entry["cert_id"], entry["serial"]),
                                        revoked,
                                        issued_at,
                                    )
                                    for entry in parsed["signatures"]
                                )
                            else:
                                ok = True
            except (ValueError, TypeError, KeyError):
                ok = False
        results.append(ok)

    passed = sum(1 for result in results if result)
    return {
        "results": results,
        "passed": passed,
        "failed": len(results) - passed,
    }
