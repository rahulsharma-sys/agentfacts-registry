# SPDX-License-Identifier: Apache-2.0
"""SQLite persistence for agent records and their capabilities."""

from __future__ import annotations

import sqlite3
from typing import Any


class DuplicateId(Exception):  # noqa: N818
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
