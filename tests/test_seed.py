# SPDX-License-Identifier: Apache-2.0
import sqlite3

import pytest

from agentfacts import seed, service, store


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    store.init_db(c)
    yield c
    c.close()


def test_seed_registers_verified_sample(conn):
    aid = seed.seed_sample_agent(conn)
    assert aid.startswith("did:key:z")
    res = service.resolve(conn, aid)
    assert res.verified is True
    assert res.facts["handle"] == "@sample/agent"


def test_seed_is_idempotent_and_stable(conn):
    aid1 = seed.seed_sample_agent(conn)
    aid2 = seed.seed_sample_agent(conn)  # second call must not raise
    assert aid1 == aid2  # deterministic id, stable across restarts


def test_sample_is_discoverable(conn):
    aid = seed.seed_sample_agent(conn)
    hits = service.search(conn, capability="weather.forecast")
    assert any(r["id"] == aid for r in hits)
