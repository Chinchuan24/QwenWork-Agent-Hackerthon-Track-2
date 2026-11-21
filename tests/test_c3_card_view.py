"""C3 display tests, not claims of gateway enforcement."""
from copy import deepcopy
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from aegis.card_view import project_cards


def card(helper_id="support-1"):
    return dict(helper_id=helper_id, name="Support", job="Draft reprint replies",
                read_folders=["inbox", "notes"], read_sensitivity=["public", "internal"],
                never_read=["finance", "admin/owner_records.md"], alone=["Draft replies"],
                ask=["Place an order"], never=["Upload personal data"],
                money_limits={"currency": "SGD", "per_action": "0", "per_day": "0"},
                version=2, frozen=False)


def render(view, role="auditor"):
    env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / "templates"),
                      autoescape=select_autoescape(["html"]))
    return env.get_template("helper_cards.html").render(
        card_view=view, user={"username": "Reader", "role": role}, live_mode=True)


def test_exact_detached_projection_and_same_names_unique_ids():
    rows = [card(), card("support-2")]
    expected = deepcopy(rows)
    rows[0]["private_evidence"] = "withheld fixture"
    view = project_cards(rows, role="auditor")
    assert view == {"status": "ready", "cards": expected, "enforcement_connected": False}
    view["cards"][0]["alone"].append("changed display")
    assert rows[0]["alone"] == ["Draft replies"]


@pytest.mark.parametrize("role", [None, "agent", "viewer", "unknown"])
def test_wrong_role_refused_before_input_read(role):
    with pytest.raises(PermissionError):
        project_cards(object(), role=role)


@pytest.mark.parametrize("role", ["admin", "approver", "auditor"])
def test_read_roles_have_no_edit_controls(role):
    html = render(project_cards([card()], role=role), role)
    assert "No helper can edit cards through this view" in html
    assert 'action="/helper' not in html
    content = html.split("<main", 1)[1].split('>', 1)[1].split("</main>", 1)[0]
    assert "<form" not in content
    assert "<input" not in content and "<textarea" not in content


@pytest.mark.parametrize("rows,status", [(None, "missing"), ([], "missing"),
    ([card(), card()], "unreadable"), ([{}], "unreadable"), ("bad", "unreadable")])
def test_no_usable_card_shows_refusal(rows, status):
    view = project_cards(rows, role="auditor")
    assert view == {"status": status, "cards": [], "enforcement_connected": False}
    assert "No usable card to display" in render(view)
    assert "all actions refused" not in render(view)


@pytest.mark.parametrize("field,value", [("frozen", "false"), ("version", True),
    ("version", 0), ("helper_id", ""), ("read_folders", "finance"),
    ("read_sensitivity", ["unknown"]), ("money_limits", {})])
def test_invalid_contract_not_shown_as_permission(field, value):
    row = card()
    row[field] = value
    assert project_cards([row], role="auditor") == {"status": "unreadable", "cards": [], "enforcement_connected": False}


def test_all_fields_frozen_escaping_and_no_private_extras():
    row = card()
    row["name"] = '<script>bad()</script>'
    row["frozen"] = True
    row["secret"] = "withheld fixture"
    html = render(project_cards([row], role="auditor"))
    for text in ["support-1", "Draft reprint replies", "inbox", "internal", "finance",
                 "Draft replies", "Place an order", "Upload personal data", "SGD", "Version 2",
                 "Frozen: yes", "&lt;script&gt;"]:
        assert text in html
    assert "withheld fixture" not in html and "<script>bad()" not in html
    for claim in ["compliant", "certified", "approved by", "guarantees"]:
        assert claim not in html.lower()


def test_next_snapshot_shows_new_version_and_freeze():
    row = card()
    old = project_cards([row], role="auditor")
    row.update(version=3, frozen=True)
    new = project_cards([row], role="auditor")
    assert old["cards"][0]["version"] == 2
    assert new["cards"][0]["version"] == 3
    assert new["cards"][0]["frozen"] is True


@pytest.mark.parametrize("flag", [None, False, 1, "true", {}, []])
def test_only_explicit_adapter_true_reports_connected(flag):
    row = card()
    row["enforcement_connected"] = True
    view = project_cards([row], role="auditor", enforcement_connected=flag)
    assert view["enforcement_connected"] is False
    assert "Enforcement: not connected" in render(view)


def test_connected_is_status_not_action_authorization():
    for rows in ([card()], None, "bad"):
        view = project_cards(rows, role="auditor", enforcement_connected=True)
        assert view["enforcement_connected"] is True
        html = render(view)
        assert "Enforcement: connected" in html
        assert "These cards do not authorize actions" in html
        assert "all actions refused" not in html


def test_absent_template_flag_does_not_claim_connection():
    html = render({"status": "ready", "cards": [card()]})
    assert "Enforcement: not connected" in html
