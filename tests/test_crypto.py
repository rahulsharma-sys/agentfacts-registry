# SPDX-License-Identifier: Apache-2.0
import pytest

from agentfacts.crypto import (
    canonical_json,
    did_key,
    did_key_to_public_raw,
    generate_keypair,
    mb_decode,
    mb_encode,
)


def test_mb_round_trip():
    raw = bytes(range(32))
    assert mb_encode(raw).startswith("z")
    assert mb_decode(mb_encode(raw)) == raw


def test_mb_decode_rejects_non_z():
    with pytest.raises(ValueError):
        mb_decode("Qabc")


def test_did_key_round_trip():
    pub = bytes(range(32))
    did = did_key(pub)
    assert did.startswith("did:key:z")
    assert did_key_to_public_raw(did) == pub


def test_did_key_rejects_bad_prefix():
    with pytest.raises(ValueError):
        did_key_to_public_raw("did:web:example.com")


def test_generate_keypair_returns_multibase_pair():
    priv, pub = generate_keypair()
    assert priv.startswith("z") and pub.startswith("z")
    assert len(mb_decode(priv)) == 32
    assert len(mb_decode(pub)) == 32


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
