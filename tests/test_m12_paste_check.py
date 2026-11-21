"""M12 — the paste check must use an ABSOLUTE overlap count (padding the
email must not dilute a pasted paragraph below a ratio) and must scan the
subject as well as the body."""
import uuid
import pytest

pytestmark = pytest.mark.usefixtures("reviewed14_sandbox_tools")

from aegis import detectors, gateway, world
from conftest import make_session

FRAG = "Acme Industries (rosa@acme.example, tan@acme.example)"
PADDED = FRAG + " and some ordinary unrelated words to fill the message out a bit more"


def test_m12_dilution_evasion_exists_in_ratio_only_check():
    # documents the defect: the ratio alone falls below 0.3 under padding
    doc = world.SEED["documents"]["doc_client_list"]["body"]
    assert detectors.text_overlap(PADDED, doc) < 0.3


def test_m12_absolute_overlap_detects_diluted_paste():
    doc = world.SEED["documents"]["doc_client_list"]["body"]
    assert detectors.pasted_text(PADDED, doc)
    assert not detectors.pasted_text("a perfectly ordinary update about nothing at all", doc)


def test_m12_diluted_paste_in_body_blocked():
    rid, s = make_session()
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "client info",
                               "body": PADDED}, uuid.uuid4().hex)
    assert out["verdict"] in ("block", "hold")
    w = gateway.get_world(rid)
    assert not w.sent


def test_m12_paste_in_subject_blocked():
    rid, s = make_session()
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": PADDED,
                               "body": "see subject"}, uuid.uuid4().hex)
    assert out["verdict"] in ("block", "hold")
    w = gateway.get_world(rid)
    assert not w.sent


def test_m12_normal_email_still_allowed():
    rid, s = make_session()
    out = gateway.handle_call(s["token"], "send_email",
                              {"to": "rosa@acme.example", "subject": "Q3 report",
                               "body": "Please find your Q3 report attached."}, uuid.uuid4().hex)
    assert out["verdict"] == "allow"