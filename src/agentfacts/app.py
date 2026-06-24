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


def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    store.init_db(conn)  # idempotent: CREATE TABLE IF NOT EXISTS
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
def register(  # noqa: B008
    body: RegisterBody,
    conn: sqlite3.Connection = Depends(get_conn),  # noqa: B008
) -> dict[str, Any]:
    return service.register(conn, body.facts, body.controller_sig).model_dump()


@app.get("/agents")
def search(  # noqa: B008
    capability: str | None = None,
    handle: str | None = None,
    q: str | None = None,
    include_revoked: bool = False,
    conn: sqlite3.Connection = Depends(get_conn),  # noqa: B008
) -> list[dict[str, Any]]:
    return service.search(conn, capability, handle, q, include_revoked)


@app.get("/agents/{agent_id}")
def resolve(  # noqa: B008
    agent_id: str,
    conn: sqlite3.Connection = Depends(get_conn),  # noqa: B008
) -> dict[str, Any]:
    return service.resolve(conn, agent_id).model_dump()


@app.get("/agents/{agent_id}/facts.jsonld")
def facts(  # noqa: B008
    agent_id: str,
    conn: sqlite3.Connection = Depends(get_conn),  # noqa: B008
) -> dict[str, Any]:
    return service.resolve(conn, agent_id).facts or {}


@app.post("/agents/{agent_id}/rotate")
def rotate(  # noqa: B008
    agent_id: str,
    body: RotateBody,
    conn: sqlite3.Connection = Depends(get_conn),  # noqa: B008
) -> dict[str, Any]:
    return service.rotate(
        conn, agent_id, body.new_assertion_key, body.controller_sig, body.facts
    ).model_dump()


@app.post("/agents/{agent_id}/revoke")
def revoke(  # noqa: B008
    agent_id: str,
    body: RevokeBody,
    conn: sqlite3.Connection = Depends(get_conn),  # noqa: B008
) -> dict[str, Any]:
    return service.revoke(conn, agent_id, body.controller_sig).model_dump()


@app.post("/verify")
def verify(facts: dict[str, Any] = Body(...)) -> dict[str, Any]:  # noqa: B008
    ok, reason = service.verify_facts(facts)
    return {"verified": ok, "reason": reason}
