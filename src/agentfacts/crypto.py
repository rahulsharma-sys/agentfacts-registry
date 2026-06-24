# SPDX-License-Identifier: Apache-2.0
"""Ed25519 signing, multibase/did:key encoding, and canonical JSON.

All raw keys and signatures are multibase base58btc: a "z" prefix followed by
base58.b58encode(raw). The agent id is a did:key over the controller public key
(0xed01 Ed25519 multicodec), so the controller key is recoverable from the id.
"""

from __future__ import annotations

import json

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

_ED25519_MULTICODEC = b"\xed\x01"
_DID_PREFIX = "did:key:z"


def mb_encode(raw: bytes) -> str:
    return "z" + base58.b58encode(raw).decode("ascii")


def mb_decode(s: str) -> bytes:
    if not s.startswith("z"):
        raise ValueError("expected multibase base58btc ('z' prefix)")
    return base58.b58decode(s[1:])


def did_key(public_raw: bytes) -> str:
    return _DID_PREFIX + base58.b58encode(_ED25519_MULTICODEC + public_raw).decode("ascii")


def did_key_to_public_raw(did: str) -> bytes:
    if not did.startswith(_DID_PREFIX):
        raise ValueError("not an ed25519 did:key")
    data = base58.b58decode(did[len(_DID_PREFIX) :])
    if data[:2] != _ED25519_MULTICODEC:
        raise ValueError("not an ed25519 did:key")
    return data[2:]


def generate_keypair() -> tuple[str, str]:
    """Return (private_multibase, public_multibase)."""
    sk = Ed25519PrivateKey.generate()
    raw_priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return mb_encode(raw_priv), mb_encode(raw_pub)


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sign(private_mb: str, data: bytes) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(mb_decode(private_mb))
    return mb_encode(sk.sign(data))


def verify(public_mb: str, sig_mb: str, data: bytes) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(mb_decode(public_mb))
        pub.verify(mb_decode(sig_mb), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def signing_payload(facts: dict) -> bytes:
    return canonical_json({k: v for k, v in facts.items() if k != "signature"})


def statement_bytes(
    op: str, agent_id: str, epoch: int, new_assertion_key: str | None = None
) -> bytes:
    stmt: dict = {"op": op, "id": agent_id, "epoch": epoch}
    if new_assertion_key is not None:
        stmt["new_assertion_key"] = new_assertion_key
    return canonical_json(stmt)
