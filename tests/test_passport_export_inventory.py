"""Proof-pack inventory contract; not execution evidence."""
from copy import deepcopy
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis import gateway, proof_pack
from aegis.tool_passport_registry import SandboxToolRegistry
from test_c4_proof_pack import access, build, context, isolated_audit


@pytest.fixture
def inventory_registry(monkeypatch):
    records = [{"name": name, "description": "Private description " + name,
                "input_schema": {"private_inventory_field": {"type": "string"}}}
               for name in ("private_approved", "private_changed", "private_missing", "private_unknown")]
    changed = {**records[1], "description": "Private revised description"}
    registry = SandboxToolRegistry(records[:3], [records[3], changed, records[0]])
    monkeypatch.setattr(gateway, "_sandbox_tool_registry", lambda: registry)
    return registry, records, changed


def test_export_inventory_full_union_masked_hashes_and_status(access, inventory_registry):
    registry, records, changed = inventory_registry
    pack = build(access)
    assert "tool_passport_inventory" in pack, "proof pack omits the passport snapshot"
    inventory = pack["tool_passport_inventory"]
    assert inventory["status"] == "available"
    expected = []
    for row in registry.proof_rows():
        name_ref = "ref:" + hashlib.sha256(json.dumps(row["name"]).encode()).hexdigest()
        expected.append({**row, "name": name_ref})
    assert [{k: v for k, v in row.items() if k != 'name'} for row in inventory['rows']] == [
        {k: v for k, v in row.items() if k != 'name'} for row in expected]
    assert len({row['name'] for row in inventory['rows']}) == len(expected)
    assert all(row['name'].startswith('ref:') for row in inventory['rows'])
    assert [(r["status"], r["reason"]) for r in inventory["rows"]] == [
        ("allow", "approved_manifest"), ("hold", "manifest_changed"),
        ("block", "missing_tool"), ("block", "unknown_tool")]
    encoded = json.dumps(pack)
    for record in records + [changed]:
        assert record["name"] not in encoded
        assert record["description"] not in encoded
    assert "private_inventory_field" not in encoded


def test_export_inventory_unavailable_is_not_empty(access, monkeypatch):
    monkeypatch.setattr(gateway, "_sandbox_tool_registry", lambda: SandboxToolRegistry([], []))
    empty = build(access)
    assert "tool_passport_inventory" in empty, "proof pack omits empty inventory state"
    assert empty["tool_passport_inventory"] == {"status": "available", "rows": []}
    def unavailable():
        raise ValueError("private approval catalog failure")
    monkeypatch.setattr(gateway, "_sandbox_tool_registry", unavailable)
    pack = build(access)
    assert pack["tool_passport_inventory"] == {"status": "unavailable", "rows": []}
    assert "private approval catalog failure" not in json.dumps(pack)


@pytest.mark.parametrize("field,value", [
    ("name", "ref:" + "0" * 64), ("candidate_sha256", "0" * 64),
    ("approved_sha256", "0" * 64), ("status", "block")])
def test_export_seal_covers_inventory(access, inventory_registry, field, value):
    key = Ed25519PrivateKey.generate()
    artifact = proof_pack.build_proof_pack(0, time.time() + 10, context=context(access), signing_key=key)
    assert proof_pack.verify_seal(artifact, key.public_key())
    original = json.loads(artifact)
    assert "tool_passport_inventory" in original["payload"], "seal has no inventory to protect"
    changed = deepcopy(original)
    row = changed["payload"]["tool_passport_inventory"]["rows"][0]
    assert row[field] != value
    row[field] = value
    assert not proof_pack.verify_seal(json.dumps(changed), key.public_key())
