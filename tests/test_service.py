# SPDX-License-Identifier: Apache-2.0
import pytest

from agentfacts import crypto, service
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
    other = make_identity()
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


def _rotate_sig(idn, new_assert_pub, epoch):
    return crypto.sign(
        idn["ctrl_priv"],
        crypto.statement_bytes("rotate", idn["id"], epoch, new_assertion_key=new_assert_pub),
    )


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
    with pytest.raises(ServiceError) as e:
        service.rotate(conn, idn["id"], new_pub, _rotate_sig(idn, new_pub, 2), new_facts)
    assert e.value.reason == "epoch_stale"


def test_rotate_rejects_wrong_controller(conn):
    idn = _registered(conn)
    attacker = make_identity()
    new_priv, new_pub = crypto.generate_keypair()
    new_facts = build_signed_facts(idn, epoch=2, assert_priv=new_priv, assert_pub=new_pub)
    bad = crypto.sign(
        attacker["ctrl_priv"],
        crypto.statement_bytes("rotate", idn["id"], 2, new_assertion_key=new_pub),
    )
    with pytest.raises(ServiceError) as e:
        service.rotate(conn, idn["id"], new_pub, bad, new_facts)
    assert e.value.reason == "controller_sig_invalid"


def test_revoke_then_resolve_unverified_and_unsearchable(conn):
    idn = _registered(conn)
    service.revoke(conn, idn["id"], _revoke_sig(idn, 1))
    res = service.resolve(conn, idn["id"])
    assert res.verified is False and res.reason == "revoked"
    assert service.search(conn, capability="weather.forecast") == []
