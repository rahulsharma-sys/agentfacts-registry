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
    with pytest.raises(Exception):  # noqa: B017
        RotateBody()  # type: ignore[call-arg]
    body = RotateBody(new_assertion_key="zNEW", controller_sig="zSIG", facts={"id": "x"})
    assert body.new_assertion_key == "zNEW"


def test_revoke_body():
    assert RevokeBody(controller_sig="zSIG").controller_sig == "zSIG"
