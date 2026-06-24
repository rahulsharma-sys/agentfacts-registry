# SPDX-License-Identifier: Apache-2.0
import sqlite3

import pytest

from agentfacts import store


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    store.init_db(c)
    yield c
    c.close()


def _rec(agent_id="did:key:zA", caps=("weather.forecast",)):
    return {
        "id": agent_id,
        "handle": "@alice/weather",
        "endpoint": "https://a.example",
        "controller_key": "zCTRL",
        "assertion_key": "zASSERT",
        "epoch": 1,
        "status": "active",
        "facts_json": '{"id":"%s"}' % agent_id,  # noqa: UP031
        "issued_at": "2026-06-24T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "updated_at": "2026-06-24T00:00:00Z",
    }, list(caps)


def test_insert_and_get(conn):
    rec, caps = _rec()
    store.insert_agent(conn, rec, caps)
    got = store.get_agent(conn, "did:key:zA")
    assert got["handle"] == "@alice/weather"
    assert got["status"] == "active"


def test_insert_duplicate_raises(conn):
    rec, caps = _rec()
    store.insert_agent(conn, rec, caps)
    with pytest.raises(store.DuplicateId):
        store.insert_agent(conn, rec, caps)


def test_search_by_capability(conn):
    a, _ = _rec("did:key:zA", caps=("weather.forecast",))
    b, _ = _rec("did:key:zB", caps=("nl.summarize",))
    store.insert_agent(conn, a, ["weather.forecast"])
    store.insert_agent(conn, b, ["nl.summarize"])
    ids = {r["id"] for r in store.search_agents(conn, capability="weather.forecast")}
    assert ids == {"did:key:zA"}


def test_revoke_hides_from_search(conn):
    rec, caps = _rec()
    store.insert_agent(conn, rec, caps)
    store.set_status(conn, "did:key:zA", "revoked")
    assert store.search_agents(conn, capability="weather.forecast") == []
    assert store.search_agents(conn, capability="weather.forecast", include_revoked=True) != []


def test_update_rotation(conn):
    rec, caps = _rec()
    store.insert_agent(conn, rec, caps)
    store.update_rotation(
        conn, "did:key:zA", "zNEWASSERT", 2, '{"epoch":2}', "2026-06-24T01:00:00Z"
    )  # noqa: E501
    got = store.get_agent(conn, "did:key:zA")
    assert got["assertion_key"] == "zNEWASSERT"
    assert got["epoch"] == 2
