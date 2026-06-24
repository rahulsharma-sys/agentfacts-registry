# SPDX-License-Identifier: Apache-2.0
"""Domain error with a machine-readable reason and HTTP status."""

from __future__ import annotations


class ServiceError(Exception):
    def __init__(self, reason: str, status: int = 400) -> None:
        self.reason = reason
        self.status = status
        super().__init__(reason)
