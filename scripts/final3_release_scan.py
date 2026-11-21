"""Bounded current-release and single-root blob scan, no private source history."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(sys.argv[1]).resolve()
assert ROOT.name == 'twinguard-release'
def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)
assert git('rev-list', '--count', 'HEAD').strip() == b'1'
patterns = {
    'private-key': rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'provider-token': rb'\b(?:sk-[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})\b',
    'credential-literal': rb'(?i)(?:api_key|password|secret|token)\s*[:=]\s*["\x27][^"\x27\n]{12,}["\x27]',
}
rows, candidates = [], []
dispositions = {
    ('aegis/redteam.py', '7fbb32cb4621cf1cbc24c42de84eaf3c3037dbdb1d705f3170fb7769119fc362'): 'run_scenario deliberately substitutes invalid-token-for-test only for bad_token attacks; legitimate token is allocated by start_session.',
    ('tests/test_auth_password_regression.py', '58a3f9a7f8ba1b02d13e3f0d94a49561e1a0dd7b30691f3bf2940acfda47b9e8'): 'Missing-session sentinel in password revocation test, distinct from generated current/foreign session tokens.',
    ('tests/test_c4_proof_pack.py', '65bb0481daea49c47cc95d47dc6874ddeab03893d64d0a26d50699d8e770ec4c'): 'Synthetic unmatched rule prose, injected into caller row and asserted absent from masked proof export.',
    ('tests/test_c4_proof_pack.py', 'c817f613321fabf01c922470dde949c9b528a7230260d92476346827d5f93e4d'): 'Synthetic launch-plan prose inserted into temporary audit decision; export masking assertion.',
    ('tests/test_c4_proof_pack.py', '19a52518aa49648398f8fdf0dfd0ad48c5c95d08f14fdc1b2f3952f27cbd6c06'): 'Synthetic caller prose and reserved .invalid URL, injected into catalog projection and asserted not exported.',
    ('tests/test_detectors.py', '1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3'): 'AWS documented EXAMPLE access-key identifier, detector input only; no secret access key or authentication call.',
    ('tests/test_g1_metrics_screen.py', 'b8d8130af5e026f742a98fc268c64d3a3a38f5de4dfec062c7d9fa4034ced842'): 'Password supplied to create_user for UUID-named temporary test account and used by local TestClient login.',
    ('tests/test_g1_view_route.py', '85873df367d08012eb3b6d8beef7521e5fc78a3cd00b5d04b8cc6dd80a6c2c7c'): 'Password created explicitly for UUID-named synthetic approver fixture in isolated test database.',
    ('tests/test_g1_view_route.py', '24d048098ef7cf15abf07f83644431f6bcd46bb1cc053c3b6221812e80bfafc5'): 'Password created for synthetic creator/viewer accounts to test authenticated denial, not a production credential.',
    ('tests/test_new_attacks_delta.py', 'f4ee43c6b967e208963baa83ebe3846f7a0cae3c78f48ab5a766f49d0832ef56'): 'Synthetic Meridian world registered password: aegis/world.py doc_credentials body; test asserts known_secrets membership and blocked egress.',
    ('tests/test_new_attacks_delta.py', '2f5e2bd69510c3c86b5257a1d56129f0cc8912add5793b1820206604eee4733c'): 'Same synthetic world password used to construct base32, ROT13, decimal and fragment detector regression cases.',
    ('tests/test_new_attacks_identity.py', 'ed19c09d58f27fd18294de82c621a94ff4ad981f82a1606239ec3286ff0e5500'): 'Forged copied-owner-token string placed in caller arguments; stopped() asserts no sandbox send and card remains unchanged.',
    ('tests/test_proof_pack_receipt_bindings.py', '66d6226884fe182b3144912ddfb7c40736d437c41fbb2b3dba06eb861086cc17'): 'Synthetic reviewer/baseline text used in local audit records, opaque receipt linkage asserted and clear literal excluded.',
    ('tests/test_t8_briefing.py', 'bd851ad24fcca2cf6731fa832f3ae8791e7d6151b569867cef60ef2bedf24db2'): 'Synthetic malicious instruction and numeric bank placeholder in in-memory rows; briefing excludes script, amount and literal.',
}
for raw in git('ls-files', '-z').split(b'\0'):
    if not raw:
        continue
    name = raw.decode()
    path = ROOT / name
    assert not path.is_symlink() and path.is_file()
    assert path.name == '.env.example' or not path.name.startswith('.env')
    assert path.stat().st_size <= 5 * 1024 * 1024
    data = path.read_bytes()
    blob = git('show', 'HEAD:' + name)
    assert data == blob
    rows.append(dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    for label, pattern in patterns.items():
        for match in re.finditer(pattern, data):
            line = data[:match.start()].count(b'\n') + 1
            fingerprint = hashlib.sha256(match.group()).hexdigest()
            disposition = dispositions.get((name, fingerprint))
            candidates.append(dict(path=name, line=line, detector=label,
                disposition=disposition or 'UNRESOLVED: new or changed candidate requires inspection',
                status='synthetic-reviewed' if disposition else 'unresolved', fingerprint=fingerprint))
result = dict(commit=git('rev-parse', 'HEAD').decode().strip(), file_count=len(rows),
    root_commit_count=1, max_file_bytes=5 * 1024 * 1024, files=rows, candidates=candidates,
    confirmed_real_secrets=0, zero_real_secrets_proven=all(c['status'] == 'synthetic-reviewed' for c in candidates),
    scope='Sibling release current tracked files and its only root commit; private historical repo never published and explicitly outside go-live scope.',
    limitation='Zero real secrets within bounded detector scope after fingerprint-bound source provenance review; not a mathematical proof against arbitrary encodings. New or changed candidates fail closed.')
Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: result[k] for k in ('commit', 'file_count', 'root_commit_count', 'confirmed_real_secrets', 'zero_real_secrets_proven')}))
