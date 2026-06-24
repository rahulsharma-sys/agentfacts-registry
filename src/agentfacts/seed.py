# SPDX-License-Identifier: Apache-2.0
"""Seed a deterministic sample agent so discovery is non-empty on a fresh instance.

The deployed free-tier instance uses ephemeral storage, so a cold start begins with
an empty database. Registering one stable sample agent on startup means a judge can
always discover, resolve, and verify something without registering first. Keys derive
from a fixed seed, so the sample's id is identical across restarts and re-running the
seed is a no-op (idempotent).
"""

from __future__ import annotations

import hashlib
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agentfacts import crypto, service
from agentfacts.errors import ServiceError

_SAMPLE_NS = "agentfacts-sample-v1"


def _det_keypair(label: str) -> tuple[str, str]:
    """Deterministic Ed25519 keypair (multibase) from a fixed label."""
    raw = hashlib.sha256(f"{_SAMPLE_NS}/{label}".encode()).digest()
    sk = Ed25519PrivateKey.from_private_bytes(raw)
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return crypto.mb_encode(priv), crypto.mb_encode(pub)


def build_sample() -> tuple[dict, str]:
    """Return (signed facts, controller_sig) for the sample agent."""
    ctrl_priv, ctrl_pub = _det_keypair("controller")
    assert_priv, assert_pub = _det_keypair("assertion")
    agent_id = crypto.did_key(crypto.mb_decode(ctrl_pub))
    facts: dict = {
        "@context": "https://spec.projectnanda.org/agentfacts/v1.2.jsonld",
        "id": agent_id,
        "handle": "@sample/agent",
        "owner": "nanda-demo",
        "endpoints": ["https://agentfacts-registry.onrender.com"],
        "capabilities": ["weather.forecast", "demo.hello"],
        "assertion_key": assert_pub,
        "epoch": 1,
        "issued_at": "2026-06-24T00:00:00Z",
        "expires_at": "2999-01-01T00:00:00Z",
        "meta": {"note": "Auto-seeded sample agent for discovery demos."},
    }
    facts["signature"] = {
        "alg": "ed25519",
        "key": assert_pub,
        "value": crypto.sign(assert_priv, crypto.signing_payload(facts)),
    }
    controller_sig = crypto.sign(
        ctrl_priv, crypto.statement_bytes("register", agent_id, 1, new_assertion_key=assert_pub)
    )
    return facts, controller_sig


def seed_sample_agent(conn: sqlite3.Connection) -> str:
    """Register the sample agent if absent. Idempotent; returns the sample agent id."""
    facts, controller_sig = build_sample()
    try:
        service.register(conn, facts, controller_sig)
    except ServiceError as exc:
        if exc.reason != "already_exists":
            raise
    return facts["id"]
