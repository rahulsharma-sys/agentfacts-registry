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
