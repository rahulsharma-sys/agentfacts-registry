# SPDX-License-Identifier: Apache-2.0
"""FastAPI surface for the AgentFacts registry."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from agentfacts import crypto, service, store
from agentfacts.errors import ServiceError
from agentfacts.models import KeySet, RegisterBody, RevokeBody, RotateBody

app = FastAPI(title="AgentFacts Registry", version="0.1.0")

_DB_PATH = os.environ.get("AGENTFACTS_DB", "agentfacts.db")
_GITHUB = "https://github.com/rahulsharma-sys/agentfacts-registry"
_FAVICON = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
    "%3Ccircle cx='16' cy='16' r='13' fill='%236d5cff'/%3E"
    "%3Ccircle cx='16' cy='16' r='5' fill='white'/%3E%3C/svg%3E"
)
_LANDING_HTML = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentFacts Registry</title>
<link rel="icon" href="{_FAVICON}">
<style>
  :root{{color-scheme:dark}} *{{box-sizing:border-box}}
  body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#0c0d12;color:#e7e7ea;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;padding:2rem}}
  .wrap{{max-width:640px;width:100%}}
  .badge{{display:inline-block;font:600 12px/1 ui-monospace,monospace;color:#a99cff;
    border:1px solid #2a2b38;border-radius:999px;padding:6px 12px;margin-bottom:20px}}
  h1{{font-size:2.2rem;margin:0 0 .5rem;letter-spacing:-.02em}}
  p.lead{{color:#a7a8b3;line-height:1.6;margin:0 0 1.75rem}}
  .grid{{display:grid;gap:12px;grid-template-columns:1fr 1fr}}
  a.card{{display:block;text-decoration:none;color:inherit;background:#14151d;
    border:1px solid #23242f;border-radius:12px;padding:16px 18px;
    transition:border-color .15s,transform .15s}}
  a.card:hover{{border-color:#6d5cff;transform:translateY(-1px)}}
  a.card .t{{font-weight:600;margin-bottom:4px}} a.card .d{{font-size:13px;color:#9092a0}}
  .full{{grid-column:1/-1}}
  code{{font-family:ui-monospace,monospace;color:#c9c2ff;background:#1a1b24;
    padding:1px 6px;border-radius:6px}}
  .foot{{margin-top:1.75rem;font-size:13px;color:#75767f;line-height:1.7}}
</style></head><body><div class="wrap">
  <span class="badge">NANDA · Internet of Agents</span>
  <h1>AgentFacts Registry</h1>
  <p class="lead">A verifiable agent identity &amp; discovery service. Agents register a
    cryptographically signed <strong>AgentFacts</strong> document, discover each other by
    capability, resolve, and verify — with key <strong>rotation and revocation that take
    effect immediately</strong>, the thing DNS can't do.</p>
  <div class="grid">
    <a class="card" href="/docs"><div class="t">API Docs →</div>
      <div class="d">Interactive OpenAPI — try every endpoint</div></a>
    <a class="card" href="/skill"><div class="t">Agent Guide →</div>
      <div class="d">SKILL.md — how an agent uses this service</div></a>
    <a class="card full" href="{_GITHUB}"><div class="t">Source on GitHub →</div>
      <div class="d">FastAPI · SQLite · Ed25519 · Apache-2.0</div></a>
  </div>
  <p class="foot">Quickstart: <code>POST /keys</code> → sign your facts →
    <code>POST /agents</code> → <code>GET /agents?capability=…</code> →
    <code>GET /agents/{{id}}</code>. Health: <code>/healthz</code>.</p>
</div></body></html>"""


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


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _LANDING_HTML


def _skill_path() -> Path | None:
    """Locate SKILL.md across layouts: explicit env, container WORKDIR, source tree."""
    candidates = [
        os.environ.get("AGENTFACTS_SKILL_PATH"),
        str(Path.cwd() / "SKILL.md"),  # container: WORKDIR /app holds SKILL.md
        str(Path(__file__).resolve().parents[2] / "SKILL.md"),  # source/editable layout
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


@app.get("/skill", response_class=PlainTextResponse)
def skill() -> str:
    path = _skill_path()
    return path.read_text(encoding="utf-8") if path else "SKILL.md not found"


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
