# SPDX-License-Identifier: Apache-2.0
import sqlite3

import pytest
from fastapi.testclient import TestClient

from agentfacts import crypto, store
from agentfacts.app import app, get_conn
from tests.conftest import build_signed_facts, make_identity, register_sig


@pytest.fixture
def client():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    store.init_db(conn)
    app.dependency_overrides[get_conn] = lambda: conn
    yield TestClient(app)
    app.dependency_overrides.clear()
    conn.close()


def _register(client, idn):
    return client.post(
        "/agents",
        json={
            "facts": build_signed_facts(idn),
            "controller_sig": register_sig(idn, idn["assert_pub"]),
        },
    )


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_full_loop(client):
    idn = make_identity()
    r = _register(client, idn)
    assert r.status_code == 200, r.text
    found = client.get("/agents", params={"capability": "weather.forecast"}).json()
    assert any(rec["id"] == idn["id"] for rec in found)
    res = client.get(f"/agents/{idn['id']}").json()
    assert res["verified"] is True
    raw = client.get(f"/agents/{idn['id']}/facts.jsonld").json()
    assert raw["id"] == idn["id"]


def test_register_bad_signature_400(client):
    idn = make_identity()
    facts = build_signed_facts(idn)
    facts["signature"]["value"] = facts["signature"]["value"][:-2] + "00"
    r = client.post(
        "/agents",
        json={"facts": facts, "controller_sig": register_sig(idn, idn["assert_pub"])},
    )
    assert r.status_code == 400
    assert r.json()["reason"] == "signature_invalid"


def test_rotate_then_old_key_demo(client):
    idn = make_identity()
    _register(client, idn)
    new_priv, new_pub = crypto.generate_keypair()
    new_facts = build_signed_facts(idn, epoch=2, assert_priv=new_priv, assert_pub=new_pub)
    rot = client.post(
        f"/agents/{idn['id']}/rotate",
        json={
            "new_assertion_key": new_pub,
            "controller_sig": crypto.sign(
                idn["ctrl_priv"],
                crypto.statement_bytes("rotate", idn["id"], 2, new_assertion_key=new_pub),
            ),
            "facts": new_facts,
        },
    )
    assert rot.status_code == 200, rot.text
    assert client.get(f"/agents/{idn['id']}").json()["record"]["assertion_key"] == new_pub


def test_revoke_removes_from_discovery(client):
    idn = make_identity()
    _register(client, idn)
    rev = client.post(
        f"/agents/{idn['id']}/revoke",
        json={
            "controller_sig": crypto.sign(
                idn["ctrl_priv"], crypto.statement_bytes("revoke", idn["id"], 1)
            )
        },
    )
    assert rev.status_code == 200
    assert client.get(f"/agents/{idn['id']}").json()["verified"] is False
    assert client.get("/agents", params={"capability": "weather.forecast"}).json() == []


def test_keys_helper(client):
    ks = client.post("/keys").json()
    assert ks["id"].startswith("did:key:z")
    assert ks["assertion_public"].startswith("z")


def test_verify_endpoint(client):
    idn = make_identity()
    facts = build_signed_facts(idn)
    assert client.post("/verify", json=facts).json() == {"verified": True, "reason": "ok"}


def test_skill_served_from_env_path(client, tmp_path, monkeypatch):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# AgentFacts Registry\nlive skill content", encoding="utf-8")
    monkeypatch.setenv("AGENTFACTS_SKILL_PATH", str(skill_file))
    r = client.get("/skill")
    assert r.status_code == 200
    assert "live skill content" in r.text
