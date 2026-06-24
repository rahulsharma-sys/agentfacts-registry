# SPDX-License-Identifier: Apache-2.0
import sqlite3

import pytest

from agentfacts import crypto, store


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    store.init_db(c)
    yield c
    c.close()


def make_identity():
    ctrl_priv, ctrl_pub = crypto.generate_keypair()
    assert_priv, assert_pub = crypto.generate_keypair()
    agent_id = crypto.did_key(crypto.mb_decode(ctrl_pub))
    return {
        "id": agent_id,
        "ctrl_priv": ctrl_priv,
        "assert_priv": assert_priv,
        "assert_pub": assert_pub,
    }


def build_signed_facts(
    idn,
    *,
    epoch=1,
    assert_priv=None,
    assert_pub=None,
    expires_at="2999-01-01T00:00:00Z",
    capabilities=("weather.forecast",),
):
    assert_priv = assert_priv or idn["assert_priv"]
    assert_pub = assert_pub or idn["assert_pub"]
    facts = {
        "@context": "https://spec.projectnanda.org/agentfacts/v1.2.jsonld",
        "id": idn["id"],
        "handle": "@alice/weather",
        "owner": "alice",
        "endpoints": ["https://a.example/agent"],
        "capabilities": list(capabilities),
        "assertion_key": assert_pub,
        "epoch": epoch,
        "issued_at": "2026-06-24T00:00:00Z",
        "expires_at": expires_at,
        "meta": {},
    }
    sig = crypto.sign(assert_priv, crypto.signing_payload(facts))
    facts["signature"] = {"alg": "ed25519", "key": assert_pub, "value": sig}
    return facts


def register_sig(idn, assertion_pub, epoch=1):
    return crypto.sign(
        idn["ctrl_priv"],
        crypto.statement_bytes("register", idn["id"], epoch, new_assertion_key=assertion_pub),
    )
