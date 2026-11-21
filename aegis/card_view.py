"""Read-only C3 display contract. No storage, policy decisions or gateway hooks.

The integrator supplies authorized, safe-to-display metadata from its card store.
Call project_cards(rows, role=user['role']) after session authentication; map
PermissionError to HTTP 403. Render helper_cards.html with card_view=result.
Routes, re-authentication, card writes and actual enforcement belong to the app.
Money values are display strings, not amounts calculated or enforced here.
"""
from copy import deepcopy
import math
import sqlite3
import time

from cryptography.exceptions import InvalidTag

from . import db, evidence


READ_ROLES = frozenset({"admin", "approver", "auditor"})
_FIELDS = ("helper_id", "name", "job", "read_folders", "read_sensitivity",
           "never_read", "alone", "ask", "never", "money_limits", "version", "frozen")
_LISTS = ("read_folders", "read_sensitivity", "never_read", "alone", "ask", "never")
_LEVELS = frozenset({"public", "internal", "client-confidential", "regulated"})


def load_stored_cards(*, role):
    """Read the shipped storage schema without inventing absent permissions."""
    if not isinstance(role, str) or role not in READ_ROLES:
        raise PermissionError("Your role cannot view helper cards")
    view = {"status": "missing", "cards": [], "warnings": [],
            "enforcement_connected": False}
    try:
        connection = db.conn()
        if not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='helper_cards'").fetchone():
            return view
        rows = connection.execute(
            "SELECT c.helper_id, c.version, c.content, s.task_text "
            "FROM helper_cards c LEFT JOIN agent_sessions s ON s.id=c.helper_id "
            "ORDER BY c.helper_id").fetchall()
    except sqlite3.Error:
        view.update(status="unreadable", warnings=["Invalid or unreadable stored cards"])
        return view
    for row in rows:
        try:
            card = evidence.dec_json(row['content'])
            if not isinstance(card, dict) or type(row['version']) is not int or row['version'] < 1:
                raise ValueError('invalid card')
            for key in ('tools', 'read_folders', 'read_sensitivity'):
                if not isinstance(card.get(key), list) or any(not isinstance(v, str) for v in card[key]):
                    raise ValueError('invalid card lists')
            for key in ('never_read', 'alone', 'ask', 'never'):
                if key in card and (not isinstance(card[key], list) or any(
                        not isinstance(v, str) for v in card[key])):
                    raise ValueError('invalid optional list')
            if 'frozen' in card and type(card['frozen']) is not bool:
                raise ValueError('invalid freeze')
            if 'expiry' in card and (type(card['expiry']) not in (int, float)
                    or not math.isfinite(card['expiry']) or card['expiry'] <= time.time()):
                raise ValueError('invalid expiry')
            if 'money_limits' in card:
                money = card['money_limits']
                if not isinstance(money, dict) or set(money) != {'currency', 'per_action', 'per_day'}:
                    raise ValueError('invalid money')
                if not isinstance(money['currency'], str) or not money['currency'].strip():
                    raise ValueError('invalid currency')
                for key in ('per_action', 'per_day'):
                    if type(money[key]) not in (int, float) or not math.isfinite(money[key]) or money[key] < 0:
                        raise ValueError('invalid amount')
            display = {key: deepcopy(card.get(key)) for key in (
                'tools', 'read_folders', 'read_sensitivity', 'never_read',
                'alone', 'ask', 'never', 'money_limits', 'frozen', 'expiry')}
            display.update(helper_id=row['helper_id'], version=row['version'], job=row['task_text'])
            view['cards'].append(display)
        except (ValueError, TypeError, UnicodeError, InvalidTag, evidence.EvidenceKeyError):
            view['warnings'].append('Invalid or unreadable stored card: ' + row['helper_id'])
    view['status'] = 'ready' if view['cards'] else 'unreadable' if rows else 'missing'
    return view


def project_cards(rows, *, role, enforcement_connected=False):
    """Project a whole snapshot, refusing malformed or duplicate-ID snapshots.

    Input is a list of dictionaries with all _FIELDS present. Extra fields are
    dropped rather than leaking stored evidence. Empty permission lists stay empty.
    This is display validation only, never an authorization verdict for an action.
    enforcement_connected is trusted adapter metadata, not a stored card field.
    Only literal True reports connection; absent or malformed flags report false.
    The adapter must verify actual gateway wiring before supplying True.
    """
    if not isinstance(role, str) or role not in READ_ROLES:
        raise PermissionError("Your role cannot view helper cards")
    connected = enforcement_connected is True
    if rows is None or (isinstance(rows, list) and not rows):
        return {"status": "missing", "cards": [], "enforcement_connected": connected}
    invalid = {"status": "unreadable", "cards": [], "enforcement_connected": connected}
    if not isinstance(rows, list):
        return invalid
    cards = []
    ids = set()
    for row in rows:
        if not isinstance(row, dict) or any(key not in row for key in _FIELDS):
            return invalid
        if any(not isinstance(row[key], str) or not row[key].strip()
               for key in ("helper_id", "name", "job")):
            return invalid
        if row["helper_id"] in ids:
            return invalid
        if type(row["version"]) is not int or row["version"] < 1 or type(row["frozen"]) is not bool:
            return invalid
        for key in _LISTS:
            if not isinstance(row[key], list) or any(
                    not isinstance(value, str) or not value.strip() for value in row[key]):
                return invalid
        if any(level not in _LEVELS for level in row["read_sensitivity"]):
            return invalid
        money = row["money_limits"]
        if not isinstance(money, dict) or set(money) != {"currency", "per_action", "per_day"}:
            return invalid
        if any(not isinstance(value, str) or not value.strip() for value in money.values()):
            return invalid
        ids.add(row["helper_id"])
        cards.append(deepcopy({key: row[key] for key in _FIELDS}))
    return {"status": "ready", "cards": cards, "enforcement_connected": connected}
