# AgentFacts Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a hosted, verifiable NANDA-style agent identity & discovery service (register → discover → resolve → verify) with sub-second key rotation and revocation, plus a SKILL.md an agent can drive it from.

**Architecture:** A FastAPI service over four framework-independent units — `crypto` (Ed25519 + did:key + canonical JSON + sign/verify), `models` (Pydantic schemas), `store` (SQLite), `service` (domain logic) — with a thin `app` routing layer. Agents self-sign AgentFacts with a rotatable **assertion** key; a stable **controller** key (embedded in the `did:key` id) authorizes rotate/revoke. Verification is recomputed on every resolve, so rotation/revocation take effect immediately.

**Tech Stack:** Python 3.12, FastAPI, uvicorn, `cryptography` (Ed25519), `base58`, SQLite (stdlib), Pydantic v2; `pytest` + `httpx` (TestClient), `ruff`; Docker + Render for hosting.

**Spec:** `docs/superpowers/specs/2026-06-24-agentfacts-registry-design.md`.

**Key conventions used throughout (read once):**
- **Encodings:** all raw keys and signatures are **multibase base58btc** — a `"z"` prefix followed by `base58.b58encode(raw)`. The agent `id` is a **did:key**: `"did:key:z" + base58.b58encode(b"\xed\x01" + pubkey_raw)` (0xed01 = Ed25519 multicodec). The controller public key is recoverable by decoding the id — there is no separate `controller_key` field in the facts.
- **Canonicalization:** `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. The signing payload of a facts document is the **raw received dict minus the `signature` key**, canonicalized. The server canonicalizes the *raw* incoming dict (never a re-normalized model dump) so it signs exactly what the client signed.
- **Statements** (for register/rotate/revoke) are canonical JSON of `{"op": ..., "id": ..., "epoch": N[, "new_assertion_key": ...]}` signed by the **controller** key.
- **Verification of facts** = status `active` AND `expires_at` in the future AND `facts["signature"]["key"] == current registered assertion_key` AND Ed25519 verify passes.

---

## File Structure

```
agentfacts-registry/
├── pyproject.toml
├── README.md
├── SKILL.md                 # agent-facing deliverable
├── Dockerfile
├── render.yaml
├── docs/superpowers/...      # spec + this plan
├── src/agentfacts/
│   ├── __init__.py
│   ├── crypto.py            # Ed25519, multibase, did:key, canonical JSON, sign/verify, statements
│   ├── errors.py            # ServiceError(reason, status)
│   ├── models.py            # Pydantic response/request models
│   ├── store.py             # SQLite persistence
│   ├── service.py           # register/resolve/search/rotate/revoke/verify_facts
│   └── app.py               # FastAPI routes + error handler + SKILL.md serving
└── tests/
    ├── conftest.py          # shared signing helpers + client fixture
    ├── test_crypto.py
    ├── test_store.py
    ├── test_service.py
    └── test_api.py
```

---

## Phase 0 — Scaffold & environment

### Task 0.1: venv + dependencies

**Files:** none

- [ ] **Step 1: Create venv**

Run (from `~/agentfacts-registry`):
```bash
cd ~/agentfacts-registry
uv venv --python 3.12
```
Expected: `.venv` created with CPython 3.12.x.

- [ ] **Step 2: Install deps**

Run:
```bash
uv pip install fastapi "uvicorn[standard]" cryptography base58 pydantic httpx pytest ruff
```
Expected: installs without error.

- [ ] **Step 3: Verify the key imports work**

Run:
```bash
uv run python -c "import fastapi, base58; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from fastapi.testclient import TestClient; print('ok')"
```
Expected: prints `ok`.

### Task 0.2: Package skeleton + pyproject

**Files:**
- Create: `pyproject.toml`, `src/agentfacts/__init__.py`, `README.md`
- Test: `tests/test_smoke.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
# SPDX-License-Identifier: Apache-2.0
[project]
name = "agentfacts-registry"
version = "0.1.0"
description = "A verifiable NANDA-style agent identity & discovery service"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.110",
    "uvicorn[standard]>=0.29",
    "cryptography>=42.0",
    "base58>=2.1",
    "pydantic>=2.6",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "httpx>=0.27", "ruff>=0.4"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/agentfacts"]

[tool.ruff]
target-version = "py312"
line-length = 100
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP", "B", "SIM"]

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

- [ ] **Step 2: Create `src/agentfacts/__init__.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""A verifiable NANDA-style agent identity & discovery service."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Create a minimal `README.md`** (expanded in Phase 6)

```markdown
# agentfacts-registry

A verifiable NANDA-style agent identity & discovery service. See `SKILL.md` for agent usage and `docs/superpowers/specs/` for the design.
```

- [ ] **Step 4: Write a smoke test**

`tests/test_smoke.py`:
```python
# SPDX-License-Identifier: Apache-2.0
def test_package_imports():
    import agentfacts

    assert agentfacts.__version__ == "0.1.0"
```

- [ ] **Step 5: Run it**

Run: `uv run pytest tests/test_smoke.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/agentfacts/__init__.py README.md tests/test_smoke.py
git commit -m "chore: scaffold agentfacts-registry package"
```

---

## Phase 1 — Crypto core (`crypto.py`)

### Task 1.1: Multibase + did:key encoding

**Files:**
- Create: `src/agentfacts/crypto.py`
- Test: `tests/test_crypto.py`

- [ ] **Step 1: Write failing tests**

`tests/test_crypto.py`:
```python
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
```

- [ ] **Step 2: Run — expect fail**

Run: `uv run pytest tests/test_crypto.py -v`
Expected: `ModuleNotFoundError: agentfacts.crypto`.

- [ ] **Step 3: Implement the encoding half of `crypto.py`**

```python
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
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

- [ ] **Step 4: Run — expect pass**

Run: `uv run pytest tests/test_crypto.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentfacts/crypto.py tests/test_crypto.py
git commit -m "feat: multibase, did:key, canonical JSON"
```

### Task 1.2: Sign / verify + statements

**Files:**
- Modify: `src/agentfacts/crypto.py`
- Test: `tests/test_crypto.py` (append)

- [ ] **Step 1: Append failing tests**

```python
from agentfacts.crypto import (  # add to existing imports
    sign,
    signing_payload,
    statement_bytes,
    verify,
)


def test_sign_verify_round_trip():
    priv, pub = generate_keypair()
    sig = sign(priv, b"hello")
    assert verify(pub, sig, b"hello") is True


def test_verify_fails_on_tamper():
    priv, pub = generate_keypair()
    sig = sign(priv, b"hello")
    assert verify(pub, sig, b"hello!") is False


def test_verify_fails_on_wrong_key():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    sig = sign(priv, b"hello")
    assert verify(other_pub, sig, b"hello") is False


def test_signing_payload_excludes_signature():
    facts = {"id": "x", "signature": {"value": "zzz"}, "a": 1}
    assert signing_payload(facts) == canonical_json({"id": "x", "a": 1})


def test_statement_bytes_shape():
    b = statement_bytes("rotate", "did:key:zX", 2, new_assertion_key="zNEW")
    assert b == canonical_json(
        {"op": "rotate", "id": "did:key:zX", "epoch": 2, "new_assertion_key": "zNEW"}
    )
    b2 = statement_bytes("revoke", "did:key:zX", 3)
    assert b2 == canonical_json({"op": "revoke", "id": "did:key:zX", "epoch": 3})
```

- [ ] **Step 2: Run — expect fail** (`ImportError` for `sign`).

- [ ] **Step 3: Append implementation to `crypto.py`**

```python
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


def statement_bytes(op: str, agent_id: str, epoch: int, new_assertion_key: str | None = None) -> bytes:
    stmt: dict = {"op": op, "id": agent_id, "epoch": epoch}
    if new_assertion_key is not None:
        stmt["new_assertion_key"] = new_assertion_key
    return canonical_json(stmt)
```

- [ ] **Step 4: Run — expect pass** (11 tests total).

- [ ] **Step 5: Commit**

```bash
git add src/agentfacts/crypto.py tests/test_crypto.py
git commit -m "feat: Ed25519 sign/verify + signed statements"
```

---

## Phase 2 — Errors & models

### Task 2.1: Error type + Pydantic models

**Files:**
- Create: `src/agentfacts/errors.py`, `src/agentfacts/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write failing tests**

`tests/test_models.py`:
```python
# SPDX-License-Identifier: Apache-2.0
import pytest

from agentfacts.errors import ServiceError
from agentfacts.models import RevokeBody, RotateBody


def test_service_error_carries_reason_and_status():
    e = ServiceError("revoked", 410)
    assert e.reason == "revoked"
    assert e.status == 410


def test_service_error_defaults_to_400():
    assert ServiceError("bad").status == 400


def test_rotate_body_requires_fields():
    with pytest.raises(Exception):
        RotateBody()  # type: ignore[call-arg]
    body = RotateBody(new_assertion_key="zNEW", controller_sig="zSIG", facts={"id": "x"})
    assert body.new_assertion_key == "zNEW"


def test_revoke_body():
    assert RevokeBody(controller_sig="zSIG").controller_sig == "zSIG"
```

- [ ] **Step 2: Run — expect fail.**

- [ ] **Step 3: Implement `src/agentfacts/errors.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""Domain error with a machine-readable reason and HTTP status."""

from __future__ import annotations


class ServiceError(Exception):
    def __init__(self, reason: str, status: int = 400) -> None:
        self.reason = reason
        self.status = status
        super().__init__(reason)
```

- [ ] **Step 4: Implement `src/agentfacts/models.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""Request/response models. Facts documents are handled as raw dicts (so the
server signs/verifies exactly what the client signed); these models cover the
non-facts request bodies and structured responses."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RotateBody(BaseModel):
    new_assertion_key: str
    controller_sig: str
    facts: dict[str, Any]


class RevokeBody(BaseModel):
    controller_sig: str


class RegisterBody(BaseModel):
    facts: dict[str, Any]
    controller_sig: str


class KeySet(BaseModel):
    id: str
    controller_private: str
    controller_public: str
    assertion_private: str
    assertion_public: str


class ResolveResult(BaseModel):
    record: dict[str, Any]
    facts: dict[str, Any] | None
    verified: bool
    reason: str
```

- [ ] **Step 5: Run — expect pass.**

- [ ] **Step 6: Commit**

```bash
git add src/agentfacts/errors.py src/agentfacts/models.py tests/test_models.py
git commit -m "feat: error type + request/response models"
```

---

## Phase 3 — Store (`store.py`)

### Task 3.1: SQLite persistence

**Files:**
- Create: `src/agentfacts/store.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write failing tests**

`tests/test_store.py`:
```python
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
        "facts_json": '{"id":"%s"}' % agent_id,
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
    store.update_rotation(conn, "did:key:zA", "zNEWASSERT", 2, '{"epoch":2}', "2026-06-24T01:00:00Z")
    got = store.get_agent(conn, "did:key:zA")
    assert got["assertion_key"] == "zNEWASSERT"
    assert got["epoch"] == 2
```

- [ ] **Step 2: Run — expect fail.**

- [ ] **Step 3: Implement `src/agentfacts/store.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""SQLite persistence for agent records and their capabilities."""

from __future__ import annotations

import sqlite3
from typing import Any


class DuplicateId(Exception):
    pass


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            handle TEXT,
            endpoint TEXT,
            controller_key TEXT,
            assertion_key TEXT,
            epoch INTEGER,
            status TEXT,
            facts_json TEXT,
            issued_at TEXT,
            expires_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_capabilities (
            agent_id TEXT,
            capability TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_caps ON agent_capabilities(capability);
        """
    )
    conn.commit()


def insert_agent(conn: sqlite3.Connection, rec: dict[str, Any], capabilities: list[str]) -> None:
    try:
        conn.execute(
            """INSERT INTO agents
               (id, handle, endpoint, controller_key, assertion_key, epoch, status,
                facts_json, issued_at, expires_at, updated_at)
               VALUES (:id, :handle, :endpoint, :controller_key, :assertion_key, :epoch,
                       :status, :facts_json, :issued_at, :expires_at, :updated_at)""",
            rec,
        )
    except sqlite3.IntegrityError as exc:
        raise DuplicateId(rec["id"]) from exc
    conn.executemany(
        "INSERT INTO agent_capabilities (agent_id, capability) VALUES (?, ?)",
        [(rec["id"], c) for c in capabilities],
    )
    conn.commit()


def get_agent(conn: sqlite3.Connection, agent_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
    return dict(row) if row else None


def search_agents(
    conn: sqlite3.Connection,
    capability: str | None = None,
    handle: str | None = None,
    q: str | None = None,
    include_revoked: bool = False,
) -> list[dict[str, Any]]:
    sql = "SELECT DISTINCT a.* FROM agents a"
    params: list[Any] = []
    where: list[str] = []
    if capability:
        sql += " JOIN agent_capabilities c ON c.agent_id = a.id"
        where.append("c.capability = ?")
        params.append(capability)
    if handle:
        where.append("a.handle = ?")
        params.append(handle)
    if q:
        where.append("(a.handle LIKE ? OR a.id LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if not include_revoked:
        where.append("a.status = 'active'")
    if where:
        sql += " WHERE " + " AND ".join(where)
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def set_status(conn: sqlite3.Connection, agent_id: str, status: str) -> None:
    conn.execute("UPDATE agents SET status = ? WHERE id = ?", (status, agent_id))
    conn.commit()


def update_rotation(
    conn: sqlite3.Connection,
    agent_id: str,
    new_assertion_key: str,
    epoch: int,
    facts_json: str,
    updated_at: str,
) -> None:
    conn.execute(
        """UPDATE agents
           SET assertion_key = ?, epoch = ?, facts_json = ?, updated_at = ?
           WHERE id = ?""",
        (new_assertion_key, epoch, facts_json, updated_at, agent_id),
    )
    conn.commit()
```

- [ ] **Step 4: Run — expect pass (5 tests).**

- [ ] **Step 5: Commit**

```bash
git add src/agentfacts/store.py tests/test_store.py
git commit -m "feat: SQLite store for agents + capabilities"
```

---

## Phase 4 — Service (`service.py`)

This is the domain core. It takes a `sqlite3.Connection` plus parsed bodies and enforces all crypto/authorization rules, raising `ServiceError(reason, status)` on failure.

### Task 4.1: register + resolve + verify_facts

**Files:**
- Create: `src/agentfacts/service.py`
- Create: `tests/conftest.py`
- Test: `tests/test_service.py`

- [ ] **Step 1: Write `tests/conftest.py` (shared signing helpers)**

```python
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


def build_signed_facts(idn, *, epoch=1, assert_priv=None, assert_pub=None, expires_at="2999-01-01T00:00:00Z", capabilities=("weather.forecast",)):
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
    return crypto.sign(idn["ctrl_priv"], crypto.statement_bytes("register", idn["id"], epoch, new_assertion_key=assertion_pub))
```

- [ ] **Step 2: Write failing tests for register/resolve/verify_facts**

`tests/test_service.py`:
```python
# SPDX-License-Identifier: Apache-2.0
import pytest

from agentfacts import service
from agentfacts.errors import ServiceError
from tests.conftest import build_signed_facts, make_identity, register_sig


def test_register_then_resolve_verified(conn):
    idn = make_identity()
    facts = build_signed_facts(idn)
    service.register(conn, facts, register_sig(idn, idn["assert_pub"]))
    res = service.resolve(conn, idn["id"])
    assert res.verified is True
    assert res.facts["handle"] == "@alice/weather"


def test_register_rejects_bad_facts_signature(conn):
    idn = make_identity()
    facts = build_signed_facts(idn)
    facts["signature"]["value"] = facts["signature"]["value"][:-2] + "00"
    with pytest.raises(ServiceError) as e:
        service.register(conn, facts, register_sig(idn, idn["assert_pub"]))
    assert e.value.reason == "signature_invalid"


def test_register_rejects_impersonation_without_controller_sig(conn):
    idn = make_identity()
    facts = build_signed_facts(idn)
    other = make_identity()  # attacker signs the register statement with the wrong controller key
    bad_sig = register_sig(other, idn["assert_pub"])
    with pytest.raises(ServiceError) as e:
        service.register(conn, facts, bad_sig)
    assert e.value.reason == "controller_sig_invalid"


def test_register_duplicate(conn):
    idn = make_identity()
    facts = build_signed_facts(idn)
    service.register(conn, facts, register_sig(idn, idn["assert_pub"]))
    with pytest.raises(ServiceError) as e:
        service.register(conn, facts, register_sig(idn, idn["assert_pub"]))
    assert e.value.reason == "already_exists"


def test_resolve_not_found(conn):
    with pytest.raises(ServiceError) as e:
        service.resolve(conn, "did:key:zNope")
    assert e.value.reason == "not_found"


def test_resolve_expired_is_unverified(conn):
    idn = make_identity()
    facts = build_signed_facts(idn, expires_at="2000-01-01T00:00:00Z")
    service.register(conn, facts, register_sig(idn, idn["assert_pub"]))
    res = service.resolve(conn, idn["id"])
    assert res.verified is False
    assert res.reason == "expired"


def test_verify_facts_stateless(conn):
    idn = make_identity()
    facts = build_signed_facts(idn)
    ok, reason = service.verify_facts(facts)
    assert ok is True and reason == "ok"
    facts["signature"]["value"] = facts["signature"]["value"][:-2] + "00"
    ok2, reason2 = service.verify_facts(facts)
    assert ok2 is False and reason2 == "signature_invalid"
```

- [ ] **Step 3: Run — expect fail.**

- [ ] **Step 4: Implement register/resolve/verify_facts in `src/agentfacts/service.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""Domain logic: register, resolve, search, rotate, revoke, verify_facts.

Raises ServiceError(reason, status) on any rule violation. Verification is
recomputed on every resolve so rotation/revocation take effect immediately.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from typing import Any

from agentfacts import crypto, store
from agentfacts.errors import ServiceError
from agentfacts.models import ResolveResult

_REQUIRED_FACTS = ("@context", "id", "handle", "assertion_key", "epoch", "expires_at", "signature")


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _parse_iso(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _require_fields(facts: dict[str, Any]) -> None:
    missing = [k for k in _REQUIRED_FACTS if k not in facts]
    if missing:
        raise ServiceError(f"missing_fields:{','.join(missing)}", 422)


def _verify_facts_signature(facts: dict[str, Any]) -> None:
    sig = facts["signature"]
    if sig.get("key") != facts["assertion_key"]:
        raise ServiceError("signature_key_mismatch", 400)
    if not crypto.verify(facts["assertion_key"], sig["value"], crypto.signing_payload(facts)):
        raise ServiceError("signature_invalid", 400)


def _controller_pub_from_id(agent_id: str) -> str:
    try:
        return crypto.mb_encode(crypto.did_key_to_public_raw(agent_id))
    except ValueError as exc:
        raise ServiceError("bad_id", 400) from exc


def register(conn: sqlite3.Connection, facts: dict[str, Any], controller_sig: str) -> ResolveResult:
    _require_fields(facts)
    if facts["epoch"] != 1:
        raise ServiceError("epoch_must_be_1", 400)
    controller_pub = _controller_pub_from_id(facts["id"])
    stmt = crypto.statement_bytes("register", facts["id"], 1, new_assertion_key=facts["assertion_key"])
    if not crypto.verify(controller_pub, controller_sig, stmt):
        raise ServiceError("controller_sig_invalid", 403)
    _verify_facts_signature(facts)

    rec = {
        "id": facts["id"],
        "handle": facts.get("handle", ""),
        "endpoint": (facts.get("endpoints") or [""])[0],
        "controller_key": controller_pub,
        "assertion_key": facts["assertion_key"],
        "epoch": 1,
        "status": "active",
        "facts_json": json.dumps(facts),
        "issued_at": facts.get("issued_at", _now_iso()),
        "expires_at": facts["expires_at"],
        "updated_at": _now_iso(),
    }
    try:
        store.insert_agent(conn, rec, list(facts.get("capabilities", [])))
    except store.DuplicateId as exc:
        raise ServiceError("already_exists", 409) from exc
    return resolve(conn, facts["id"])


def resolve(conn: sqlite3.Connection, agent_id: str) -> ResolveResult:
    rec = store.get_agent(conn, agent_id)
    if rec is None:
        raise ServiceError("not_found", 404)
    facts = json.loads(rec["facts_json"])
    verified, reason = _verify_record(rec, facts)
    return ResolveResult(record=_public_record(rec), facts=facts, verified=verified, reason=reason)


def _verify_record(rec: dict[str, Any], facts: dict[str, Any]) -> tuple[bool, str]:
    if rec["status"] != "active":
        return False, rec["status"]  # "revoked"
    if _parse_iso(rec["expires_at"]) <= dt.datetime.now(dt.timezone.utc):
        return False, "expired"
    if facts.get("signature", {}).get("key") != rec["assertion_key"]:
        return False, "signature_key_mismatch"
    if not crypto.verify(rec["assertion_key"], facts["signature"]["value"], crypto.signing_payload(facts)):
        return False, "signature_invalid"
    return True, "ok"


def _public_record(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": rec["id"],
        "handle": rec["handle"],
        "endpoint": rec["endpoint"],
        "assertion_key": rec["assertion_key"],
        "epoch": rec["epoch"],
        "status": rec["status"],
        "facts_uri": f"/agents/{rec['id']}/facts.jsonld",
        "updated_at": rec["updated_at"],
    }


def verify_facts(facts: dict[str, Any]) -> tuple[bool, str]:
    """Stateless verification of a facts doc against the key it names."""
    try:
        _require_fields(facts)
        _verify_facts_signature(facts)
    except ServiceError as e:
        return False, e.reason
    return True, "ok"
```

- [ ] **Step 5: Run — expect pass (7 tests).** Run: `uv run pytest tests/test_service.py -v`.

- [ ] **Step 6: Commit**

```bash
git add src/agentfacts/service.py tests/conftest.py tests/test_service.py
git commit -m "feat: register/resolve/verify domain logic"
```

### Task 4.2: search + rotate + revoke

**Files:**
- Modify: `src/agentfacts/service.py`
- Test: `tests/test_service.py` (append)

- [ ] **Step 1: Append failing tests**

```python
from agentfacts import crypto  # add to imports


def _rotate_sig(idn, new_assert_pub, epoch):
    return crypto.sign(idn["ctrl_priv"], crypto.statement_bytes("rotate", idn["id"], epoch, new_assertion_key=new_assert_pub))


def _revoke_sig(idn, epoch):
    return crypto.sign(idn["ctrl_priv"], crypto.statement_bytes("revoke", idn["id"], epoch))


def _registered(conn):
    idn = make_identity()
    service.register(conn, build_signed_facts(idn), register_sig(idn, idn["assert_pub"]))
    return idn


def test_search_finds_active(conn):
    idn = _registered(conn)
    hits = service.search(conn, capability="weather.forecast")
    assert any(r["id"] == idn["id"] for r in hits)


def test_rotate_invalidates_old_key(conn):
    idn = _registered(conn)
    new_priv, new_pub = crypto.generate_keypair()
    new_facts = build_signed_facts(idn, epoch=2, assert_priv=new_priv, assert_pub=new_pub)
    service.rotate(conn, idn["id"], new_pub, _rotate_sig(idn, new_pub, 2), new_facts)
    res = service.resolve(conn, idn["id"])
    assert res.verified is True
    assert res.record["assertion_key"] == new_pub
    # Re-submitting the OLD facts (old key) must now fail verification semantics:
    ok, reason = service.verify_facts(build_signed_facts(idn))  # old key, but stateless verify is self-consistent
    assert ok is True  # stateless check is about internal consistency, not rotation
    # The registry, however, rejects an old-key rotate replay:
    with pytest.raises(ServiceError) as e:
        service.rotate(conn, idn["id"], new_pub, _rotate_sig(idn, new_pub, 2), new_facts)
    assert e.value.reason == "epoch_stale"


def test_rotate_rejects_wrong_controller(conn):
    idn = _registered(conn)
    attacker = make_identity()
    new_priv, new_pub = crypto.generate_keypair()
    new_facts = build_signed_facts(idn, epoch=2, assert_priv=new_priv, assert_pub=new_pub)
    bad = crypto.sign(attacker["ctrl_priv"], crypto.statement_bytes("rotate", idn["id"], 2, new_assertion_key=new_pub))
    with pytest.raises(ServiceError) as e:
        service.rotate(conn, idn["id"], new_pub, bad, new_facts)
    assert e.value.reason == "controller_sig_invalid"


def test_revoke_then_resolve_unverified_and_unsearchable(conn):
    idn = _registered(conn)
    service.revoke(conn, idn["id"], _revoke_sig(idn, 1))
    res = service.resolve(conn, idn["id"])
    assert res.verified is False and res.reason == "revoked"
    assert service.search(conn, capability="weather.forecast") == []
```

- [ ] **Step 2: Run — expect fail.**

- [ ] **Step 3: Append implementation to `service.py`**

```python
def search(
    conn: sqlite3.Connection,
    capability: str | None = None,
    handle: str | None = None,
    q: str | None = None,
    include_revoked: bool = False,
) -> list[dict[str, Any]]:
    rows = store.search_agents(conn, capability, handle, q, include_revoked)
    return [_public_record(r) for r in rows]


def _load_active(conn: sqlite3.Connection, agent_id: str) -> dict[str, Any]:
    rec = store.get_agent(conn, agent_id)
    if rec is None:
        raise ServiceError("not_found", 404)
    return rec


def rotate(
    conn: sqlite3.Connection,
    agent_id: str,
    new_assertion_key: str,
    controller_sig: str,
    facts: dict[str, Any],
) -> ResolveResult:
    rec = _load_active(conn, agent_id)
    if rec["status"] != "active":
        raise ServiceError("revoked", 410)
    next_epoch = rec["epoch"] + 1
    controller_pub = rec["controller_key"]
    stmt = crypto.statement_bytes("rotate", agent_id, next_epoch, new_assertion_key=new_assertion_key)
    if not crypto.verify(controller_pub, controller_sig, stmt):
        raise ServiceError("controller_sig_invalid", 403)
    _require_fields(facts)
    if facts["epoch"] != next_epoch:
        raise ServiceError("epoch_stale", 409)
    if facts["assertion_key"] != new_assertion_key:
        raise ServiceError("assertion_key_mismatch", 400)
    _verify_facts_signature(facts)
    store.update_rotation(conn, agent_id, new_assertion_key, next_epoch, json.dumps(facts), _now_iso())
    return resolve(conn, agent_id)


def revoke(conn: sqlite3.Connection, agent_id: str, controller_sig: str) -> ResolveResult:
    rec = _load_active(conn, agent_id)
    stmt = crypto.statement_bytes("revoke", agent_id, rec["epoch"])
    if not crypto.verify(rec["controller_key"], controller_sig, stmt):
        raise ServiceError("controller_sig_invalid", 403)
    store.set_status(conn, agent_id, "revoked")
    return resolve(conn, agent_id)
```

- [ ] **Step 4: Run — expect pass.** Run: `uv run pytest tests/test_service.py -v`.

- [ ] **Step 5: Commit**

```bash
git add src/agentfacts/service.py tests/test_service.py
git commit -m "feat: search/rotate/revoke domain logic"
```

---

## Phase 5 — API (`app.py`)

### Task 5.1: FastAPI routes + error handling

**Files:**
- Create: `src/agentfacts/app.py`
- Test: `tests/test_api.py`

DB wiring: the app reads `AGENTFACTS_DB` (default `agentfacts.db`); a `get_conn` dependency yields a per-request connection. Tests override `get_conn` with a shared in-memory connection.

- [ ] **Step 1: Write failing API tests**

`tests/test_api.py`:
```python
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
        json={"facts": build_signed_facts(idn), "controller_sig": register_sig(idn, idn["assert_pub"])},
    )


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_full_loop(client):
    idn = make_identity()
    r = _register(client, idn)
    assert r.status_code == 200, r.text
    # discover
    found = client.get("/agents", params={"capability": "weather.forecast"}).json()
    assert any(rec["id"] == idn["id"] for rec in found)
    # resolve + verify
    res = client.get(f"/agents/{idn['id']}").json()
    assert res["verified"] is True
    # raw facts
    raw = client.get(f"/agents/{idn['id']}/facts.jsonld").json()
    assert raw["id"] == idn["id"]


def test_register_bad_signature_400(client):
    idn = make_identity()
    facts = build_signed_facts(idn)
    facts["signature"]["value"] = facts["signature"]["value"][:-2] + "00"
    r = client.post("/agents", json={"facts": facts, "controller_sig": register_sig(idn, idn["assert_pub"])})
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
            "controller_sig": crypto.sign(idn["ctrl_priv"], crypto.statement_bytes("rotate", idn["id"], 2, new_assertion_key=new_pub)),
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
        json={"controller_sig": crypto.sign(idn["ctrl_priv"], crypto.statement_bytes("revoke", idn["id"], 1))},
    )
    assert rev.status_code == 200
    assert client.get(f"/agents/{idn['id']}").json()["verified"] is False
    assert client.get("/agents", params={"capability": "weather.forecast"}).json() == []


def test_keys_helper(client):
    ks = client.post("/keys").json()
    assert ks["id"].startswith("did:key:z")
    assert ks["assertion_public"].startswith("z")
```

- [ ] **Step 2: Run — expect fail.**

- [ ] **Step 3: Implement `src/agentfacts/app.py`**

```python
# SPDX-License-Identifier: Apache-2.0
"""FastAPI surface for the AgentFacts registry."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

from agentfacts import crypto, service, store
from agentfacts.errors import ServiceError
from agentfacts.models import KeySet, RegisterBody, RevokeBody, RotateBody

app = FastAPI(title="AgentFacts Registry", version="0.1.0")

_DB_PATH = os.environ.get("AGENTFACTS_DB", "agentfacts.db")
_initialized = False


def get_conn() -> Iterator[sqlite3.Connection]:
    global _initialized
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    if not _initialized:
        store.init_db(conn)
        _initialized = True
    try:
        yield conn
    finally:
        conn.close()


@app.exception_handler(ServiceError)
async def _service_error_handler(_request: Any, exc: ServiceError) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"error": exc.reason, "reason": exc.reason})


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=PlainTextResponse)
def index() -> str:
    return "AgentFacts Registry — see /docs for OpenAPI and /skill for SKILL.md"


@app.get("/skill", response_class=PlainTextResponse)
def skill() -> str:
    path = Path(__file__).resolve().parents[2] / "SKILL.md"
    return path.read_text(encoding="utf-8") if path.exists() else "SKILL.md not found"


@app.post("/keys", response_model=KeySet)
def make_keys() -> KeySet:
    ctrl_priv, ctrl_pub = crypto.generate_keypair()
    assert_priv, assert_pub = crypto.generate_keypair()
    return KeySet(
        id=crypto.did_key(crypto.mb_decode(ctrl_pub)),
        controller_private=ctrl_priv,
        controller_public=ctrl_pub,
        assertion_private=assert_priv,
        assertion_public=assert_pub,
    )


@app.post("/agents")
def register(body: RegisterBody, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    return service.register(conn, body.facts, body.controller_sig).model_dump()


@app.get("/agents")
def search(
    capability: str | None = None,
    handle: str | None = None,
    q: str | None = None,
    include_revoked: bool = False,
    conn: sqlite3.Connection = Depends(get_conn),
) -> list[dict[str, Any]]:
    return service.search(conn, capability, handle, q, include_revoked)


@app.get("/agents/{agent_id}")
def resolve(agent_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    return service.resolve(conn, agent_id).model_dump()


@app.get("/agents/{agent_id}/facts.jsonld")
def facts(agent_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    return service.resolve(conn, agent_id).facts or {}


@app.post("/agents/{agent_id}/rotate")
def rotate(agent_id: str, body: RotateBody, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    return service.rotate(conn, agent_id, body.new_assertion_key, body.controller_sig, body.facts).model_dump()


@app.post("/agents/{agent_id}/revoke")
def revoke(agent_id: str, body: RevokeBody, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    return service.revoke(conn, agent_id, body.controller_sig).model_dump()


@app.post("/verify")
def verify(facts: dict[str, Any] = Body(...)) -> dict[str, Any]:
    ok, reason = service.verify_facts(facts)
    return {"verified": ok, "reason": reason}
```

> Note: the `_initialized` global makes the default-file path self-initialize once. In tests the `get_conn` dependency is overridden, so that path is not exercised. If a reviewer prefers, initialize the DB unconditionally per connection (idempotent `CREATE TABLE IF NOT EXISTS`) and drop the global — either is acceptable; keep whichever passes `ruff`/tests cleanly.

- [ ] **Step 4: Run — expect pass.** Run: `uv run pytest tests/test_api.py -v`.

- [ ] **Step 5: Run the full suite + ruff**

Run: `uv run pytest -q` (expect all green) and `uv run ruff check src tests` (fix any import-order/line-length issues, recommit if needed).

- [ ] **Step 6: Commit**

```bash
git add src/agentfacts/app.py tests/test_api.py
git commit -m "feat: FastAPI routes for the registry"
```

---

## Phase 6 — SKILL.md, README, deploy

### Task 6.1: SKILL.md (the Step 2 deliverable)

**Files:**
- Create: `SKILL.md`

- [ ] **Step 1: Write `SKILL.md`** with these exact sections (fill `BASE_URL` after deploy):

````markdown
# AgentFacts Registry

## What it does
A verifiable agent identity & discovery service. Register a cryptographically
signed "AgentFacts" document, let other agents discover you by capability,
resolve your record, and verify your signature — with sub-second key rotation
and revocation.

## Base URL
`BASE_URL` (e.g. https://agentfacts.onrender.com)

## Concepts
- Your identity is a `did:key` derived from a **controller** keypair (stable).
- Your facts are signed by a separate **assertion** keypair (rotatable).
- All keys/signatures are multibase base58btc: a `z` prefix + base58 of the raw bytes.
- To sign: take your JSON object, remove any `signature` field, serialize as
  canonical JSON (UTF-8, keys sorted, no spaces), and Ed25519-sign those bytes.

## Quickstart
1. `POST /keys` → returns `id`, controller + assertion key pairs. (Or bring your own.)
2. Build your AgentFacts JSON (see schema) and sign it with your assertion key.
3. `POST /agents` with `{ "facts": <signed facts>, "controller_sig": <sig> }`
   where `controller_sig` signs `{"op":"register","id":<id>,"epoch":1,"new_assertion_key":<assertion_pub>}`.
4. Discover: `GET /agents?capability=weather.forecast`
5. Resolve + verify: `GET /agents/{id}` → `{ record, facts, verified, reason }`

## Endpoints
- `POST /keys` → `{ id, controller_private, controller_public, assertion_private, assertion_public }`
- `POST /agents` (register) — body `{ facts, controller_sig }`
- `GET /agents?capability=&handle=&q=` (discover)
- `GET /agents/{id}` (resolve + verify)
- `GET /agents/{id}/facts.jsonld` (raw signed facts)
- `POST /agents/{id}/rotate` — body `{ new_assertion_key, controller_sig, facts }`;
  `controller_sig` signs `{"op":"rotate","id":<id>,"epoch":<N+1>,"new_assertion_key":<new>}`
- `POST /agents/{id}/revoke` — body `{ controller_sig }` signing `{"op":"revoke","id":<id>,"epoch":<N>}`
- `POST /verify` — body is a facts doc; returns `{ verified, reason }`
- `GET /healthz`, `GET /docs` (OpenAPI)

## AgentFacts schema
```json
{
  "@context": "https://spec.projectnanda.org/agentfacts/v1.2.jsonld",
  "id": "did:key:z...",
  "handle": "@you/yourservice",
  "owner": "you",
  "endpoints": ["https://..."],
  "capabilities": ["weather.forecast"],
  "assertion_key": "z...",
  "epoch": 1,
  "issued_at": "2026-06-24T00:00:00Z",
  "expires_at": "2027-01-01T00:00:00Z",
  "meta": {},
  "signature": {"alg": "ed25519", "key": "z...", "value": "z..."}
}
```

## Signing recipe (Python)
```python
import json, base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
def canon(o): return json.dumps(o, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()
def sign(priv_mb, data):
    sk = Ed25519PrivateKey.from_private_bytes(base58.b58decode(priv_mb[1:]))
    return "z"+base58.b58encode(sk.sign(data)).decode()
facts.pop("signature", None)
facts["signature"] = {"alg":"ed25519","key":assertion_pub,"value":sign(assertion_priv, canon(facts))}
```

## Error reasons
`signature_invalid`, `signature_key_mismatch`, `controller_sig_invalid`,
`already_exists`, `not_found`, `revoked`, `expired`, `epoch_stale`,
`assertion_key_mismatch`, `missing_fields:<list>`, `bad_id`.
````

- [ ] **Step 2: Commit**

```bash
git add SKILL.md
git commit -m "docs: SKILL.md agent guide"
```

### Task 6.2: Dockerfile + render.yaml + README

**Files:**
- Create: `Dockerfile`, `render.yaml`
- Modify: `README.md`

- [ ] **Step 1: Write `Dockerfile`**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && pip install --no-cache-dir "uvicorn[standard]"
COPY SKILL.md ./SKILL.md
ENV AGENTFACTS_DB=/app/data/agentfacts.db
RUN mkdir -p /app/data
EXPOSE 8000
CMD ["sh", "-c", "uvicorn agentfacts.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
```

- [ ] **Step 2: Write `render.yaml`**

```yaml
services:
  - type: web
    name: agentfacts-registry
    runtime: docker
    plan: free
    envVars:
      - key: AGENTFACTS_DB
        value: /app/data/agentfacts.db
    disk:
      name: data
      mountPath: /app/data
      sizeGB: 1
```

- [ ] **Step 3: Expand `README.md`** with: what it is, the one-paragraph NANDA framing, local run (`uv run uvicorn agentfacts.app:app --reload`), the `/docs` and `/skill` links, the rotation/revocation demo (curl the loop), the threat-model note (single-node, controller key authorizes changes), and links to spec + SKILL.md. Apache-2.0 license note.

- [ ] **Step 4: Smoke-test the server locally**

Run:
```bash
uv run uvicorn agentfacts.app:app --port 8000 &
sleep 2
curl -s localhost:8000/healthz
curl -s -X POST localhost:8000/keys | head -c 200
kill %1
```
Expected: `{"status":"ok"}` and a JSON keyset.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile render.yaml README.md
git commit -m "chore: Docker + Render deploy + README"
```

---

## Phase 7 — Quality gate

### Task 7.1: Lint, type, full suite, end-to-end curl

**Files:** none

- [ ] **Step 1: Ruff**

Run: `uv run ruff check src tests` → expect clean (fix + recommit if not).

- [ ] **Step 2: Full test suite**

Run: `uv run pytest -q`
Expected: all green (smoke 1, crypto 11, models 4, store 5, service 11, api 7 ≈ 39).

- [ ] **Step 3: Manual rotation demo (proves the standout end-to-end)**

Start the server, `POST /keys`, build+sign facts, `POST /agents`, `GET /agents/{id}` (verified true), rotate, then confirm the record shows the new key and a resolve is still verified while the previous signature would now be rejected. Capture the output for the README/demo.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: pass ruff + full test suite"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- §4 two-key identity (controller→did:key id, rotatable assertion) → crypto Task 1.1–1.2, service 4.1. ✓
- §5 data model (lean record + AgentFacts fields) → store 3.1, service `_public_record`, conftest `build_signed_facts`. ✓
- §6 every endpoint (keys/register/resolve/search/facts.jsonld/rotate/revoke/verify/healthz) → app 5.1 + tests. ✓
- §7 rotation/revocation/TTL authenticated by controller key, immediate effect → service 4.2 + api tests. ✓ (register hardened with `controller_sig` per the plan intro — a security strengthening over the spec's original register body.)
- §8 SKILL.md with signing recipe → Task 6.1. ✓
- §9 stack/hosting/testing → 0.1, 6.2, all test tasks. ✓
- §10 demo → Task 7.1 Step 3. ✓
- §11 open items: canonicalization is fixed (sorted-key) and reproduced in the Python snippet; did:key multicodec verified in crypto tests; exact NANDA v1.2 field names still to reconcile against the live `@context` (kept as a doc-level follow-up, does not block the build). ✓

**Placeholder scan:** No "TBD"/"handle edge cases"; every code step is complete. README body (Task 6.2 Step 3) is described prose-doc content, acceptable.

**Type/name consistency:** `mb_encode/mb_decode`, `did_key/did_key_to_public_raw`, `canonical_json/signing_payload/statement_bytes`, `sign/verify`, `register/resolve/search/rotate/revoke/verify_facts`, `ServiceError(reason,status)`, `ResolveResult`, and the error `reason` strings are used identically across crypto, service, app, and tests. The signing-payload-excludes-signature rule and the "verify against current assertion_key" rule are applied consistently in both register and resolve.

**Known follow-ups (non-blocking):** reconcile exact AgentFacts v1.2 field names with the live spec once reachable; consider RFC 8785 JCS if any client can't reproduce the sorted-key canonical form; rate-limiting and a signed audit log are future work (spec §13).
