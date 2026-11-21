import atexit
import base64
import os
import tempfile

# Canonicalize fresh allocation before config import and first signed identity.
_TMP = os.path.realpath(tempfile.mkdtemp(prefix="aegis-tests-"))
os.environ["AEGIS_DATA_DIR"] = _TMP
# external anchor for the shared test DB: outside the data folder, inside tmp
os.environ["AEGIS_ANCHOR_EXTERNAL"] = os.path.join(_TMP + "-external", "anchor.json")
# signer state: outside the data folder
os.environ["AEGIS_SIGNER_STATE"] = _TMP + "-signer"
# evidence key: generated at runtime, never committed (rule 11)
os.environ["AEGIS_EVIDENCE_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
os.environ.pop("AEGIS_QWEN_API_KEY", None)

from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# launch the session signer BEFORE importing the app modules
from aegis import config, signer_client  # noqa: E402

SIGNER = signer_client.SignerManager(os.environ["AEGIS_SIGNER_STATE"])
config.AEGIS_SIGNER_PORT = SIGNER.port
os.environ["AEGIS_SIGNER_PORT"] = str(SIGNER.port)

import pytest  # noqa: E402
from aegis import db, auth, policy, gateway, audit  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup(request):
    request.addfinalizer(SIGNER.stop)
    db.init_db()
    auth.ensure_demo_users()
    policy.ensure_default(str(ROOT / "policies" / "default.yaml"))
    policy.ensure_security_rules(str(ROOT / "policies" / "default.yaml"))
    audit.migrate_to_signer()
    from aegis import evidence
    evidence.require_key_for_startup()
    evidence.migrate_once()
    yield


@pytest.fixture(autouse=True)
def _clean_runtime():
    from aegis import evidence
    previous_key_cache = evidence._key_cache
    gateway._rate.clear()
    gateway._loops.clear()
    gateway.RUN_KILL.clear()
    auth._login_fails.clear()
    db.set_setting("kill_switch", "off", "tests", 0)
    yield
    evidence._key_cache = previous_key_cache


def _literal_test_registry(records):
    """Issue real checkpointed receipts for the literal test review only."""
    import hashlib
    import json
    import time
    from aegis.tool_passport import ToolPassport

    with gateway._PIPELINE_LOCK:
        saved = json.dumps({'version': 1, 'approved_records': records})
        digest = hashlib.sha256(saved.encode()).hexdigest()
        assert audit.verify()['ok'] is True
        db.set_setting('sandbox_tool_approvals', saved, 'literal-test-review', 0)
        review = audit.record_decision('sandbox_tools_reviewed', {
            'by': 'literal-test-review', 'version': 1, 'baseline_hash': digest,
            'fingerprints': dict(ToolPassport(records).approved)}, trusted_ts=time.time())
        assert review['checkpoint_ok'] is True
        assert audit.verify()['ok'] is True
        authority = audit.record_decision('sandbox_tools_authorized', {
            'by': 'literal-test-review', 'review_event_id': review['event_id'],
            'baseline_hash': digest}, trusted_ts=time.time())
        assert authority['checkpoint_ok'] is True
        assert audit.verify()['ok'] is True
        db.set_setting('sandbox_tool_authority', json.dumps({
            'event_id': authority['event_id'], 'baseline_hash': digest}), 'literal-test-review', 0)
        gateway._sandbox_tool_registry(remember_only=True)


@pytest.fixture
def reviewed14_sandbox_tools():
    """Literal reviewed sandbox catalog; never approve runtime discovery."""
    records = [
        {'name': 'delete_file', 'description': 'delete_file', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}}, 'required': ['doc_id']}},
        {'name': 'upload_file', 'description': 'upload_file', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}, 'target': {'type': 'string'}}, 'required': ['doc_id', 'target']}},
        {'name': 'pay_supplier', 'description': 'pay_supplier', 'input_schema': {'type': 'object', 'properties': {'supplier': {'type': 'string'}, 'amount': {'type': 'number'}, 'invoice_id': {'type': 'string'}}, 'required': ['supplier', 'amount', 'invoice_id']}},
        {'name': 'order_supplier', 'description': 'order_supplier', 'input_schema': {'type': 'object', 'properties': {'supplier': {'type': 'string'}, 'amount': {'type': 'number'}}, 'required': ['supplier', 'amount']}},
        {'name': 'accept_terms', 'description': 'accept_terms', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}, 'terms': {'type': 'string'}}, 'required': ['doc_id', 'terms']}},
        {'name': 'list_inbox', 'description': 'List inbox emails (id, sender, subject)', 'input_schema': {'type': 'object', 'properties': {}, 'required': []}},
        {'name': 'read_email', 'description': 'Read one email by id', 'input_schema': {'type': 'object', 'properties': {'email_id': {'type': 'string'}}, 'required': ['email_id']}},
        {'name': 'send_email', 'description': 'Send an email. attachment_ids is a list of document ids.', 'input_schema': {'type': 'object', 'properties': {'to': {'type': 'string'}, 'subject': {'type': 'string'}, 'body': {'type': 'string'}, 'attachment_ids': {'type': 'array', 'items': {'type': 'string'}}, 'regarding_email': {'type': 'string'}}, 'required': ['to', 'subject', 'body']}},
        {'name': 'search_files', 'description': 'Search documents by keyword', 'input_schema': {'type': 'object', 'properties': {'query': {'type': 'string'}}, 'required': ['query']}},
        {'name': 'read_file', 'description': 'Read a document by id', 'input_schema': {'type': 'object', 'properties': {'doc_id': {'type': 'string'}}, 'required': ['doc_id']}},
        {'name': 'find_contact', 'description': 'Find a contact by name or email', 'input_schema': {'type': 'object', 'properties': {'query': {'type': 'string'}}, 'required': ['query']}},
        {'name': 'get_client', 'description': 'Get client details', 'input_schema': {'type': 'object', 'properties': {'client_id': {'type': 'string'}}, 'required': ['client_id']}},
        {'name': 'fetch_web', 'description': 'Fetch an allowlisted sandbox page', 'input_schema': {'type': 'object', 'properties': {'page_id': {'type': 'string'}}, 'required': ['page_id']}},
        {'name': 'issue_refund', 'description': 'Refund an invoice. Omit amount/payee to use the ledger values.', 'input_schema': {'type': 'object', 'properties': {'invoice_id': {'type': 'string'}, 'amount': {'type': 'number'}, 'payee': {'type': 'string'}, 'note': {'type': 'string'}, 'source_email': {'type': 'string'}}, 'required': ['invoice_id']}},
    ]
    previous = db.get_setting('sandbox_tool_approvals', '')
    previous_authority = db.get_setting('sandbox_tool_authority', '')
    _literal_test_registry(records)
    try:
        yield records
    finally:
        with gateway._PIPELINE_LOCK:
            db.set_setting('sandbox_tool_approvals', previous, 'reviewed14-test-fixture', 0)
            db.set_setting('sandbox_tool_authority', previous_authority, 'reviewed14-test-fixture', 0)


@pytest.fixture
def reviewed_sandbox_tools():
    """Explicit literal review snapshot, never discovery-based approval."""
    records = [
        {'name': 'send_email',
         'description': 'Send an email. attachment_ids is a list of document ids.',
         'input_schema': {'type': 'object', 'properties': {
             'to': {'type': 'string'}, 'subject': {'type': 'string'},
             'body': {'type': 'string'},
             'attachment_ids': {'type': 'array', 'items': {'type': 'string'}},
             'regarding_email': {'type': 'string'}},
             'required': ['to', 'subject', 'body']}},
        {'name': 'order_supplier', 'description': 'order_supplier',
         'input_schema': {'type': 'object', 'properties': {
             'supplier': {'type': 'string'}, 'amount': {'type': 'number'}},
             'required': ['supplier', 'amount']}},
    ]
    previous = db.get_setting('sandbox_tool_approvals', '')
    previous_authority = db.get_setting('sandbox_tool_authority', '')
    _literal_test_registry(records)
    try:
        yield
    finally:
        with gateway._PIPELINE_LOCK:
            db.set_setting('sandbox_tool_approvals', previous, 'reviewed-test-fixture', 0)
            db.set_setting('sandbox_tool_authority', previous_authority, 'reviewed-test-fixture', 0)


def make_session(task="Help Acme Industries with their Q3 report request from Rosa.",
                 mode="enforce", by="dana"):
    rid = gateway.create_run(mode, by)
    sess = gateway.start_session(rid, task, by)
    return rid, sess