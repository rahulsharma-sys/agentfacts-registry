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
    return dt.datetime.now(dt.UTC).isoformat()


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
    stmt = crypto.statement_bytes(
        "register", facts["id"], 1, new_assertion_key=facts["assertion_key"]
    )
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
        return False, rec["status"]
    if _parse_iso(rec["expires_at"]) <= dt.datetime.now(dt.UTC):
        return False, "expired"
    if facts.get("signature", {}).get("key") != rec["assertion_key"]:
        return False, "signature_key_mismatch"
    payload = crypto.signing_payload(facts)
    if not crypto.verify(rec["assertion_key"], facts["signature"]["value"], payload):
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
    _require_fields(facts)
    if facts["epoch"] != next_epoch:
        raise ServiceError("epoch_stale", 409)
    controller_pub = rec["controller_key"]
    stmt = crypto.statement_bytes(
        "rotate", agent_id, next_epoch, new_assertion_key=new_assertion_key
    )
    if not crypto.verify(controller_pub, controller_sig, stmt):
        raise ServiceError("controller_sig_invalid", 403)
    if facts["assertion_key"] != new_assertion_key:
        raise ServiceError("assertion_key_mismatch", 400)
    _verify_facts_signature(facts)
    store.update_rotation(
        conn, agent_id, new_assertion_key, next_epoch, json.dumps(facts), _now_iso()
    )
    return resolve(conn, agent_id)


def revoke(conn: sqlite3.Connection, agent_id: str, controller_sig: str) -> ResolveResult:
    rec = _load_active(conn, agent_id)
    stmt = crypto.statement_bytes("revoke", agent_id, rec["epoch"])
    if not crypto.verify(rec["controller_key"], controller_sig, stmt):
        raise ServiceError("controller_sig_invalid", 403)
    store.set_status(conn, agent_id, "revoked")
    return resolve(conn, agent_id)
