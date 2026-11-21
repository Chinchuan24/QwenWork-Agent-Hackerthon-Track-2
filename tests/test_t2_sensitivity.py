import pytest

from aegis.sensitivity import classify


@pytest.mark.parametrize('text,level', [
    ('Website copy: Welcome to Lumen Studio.', 'public'),
    ('Published price list: website SGD 7,200.', 'public'),
    ('Marketing email received from a vendor: Our latest offers.', 'public'),
    ('Weekly plan: finish artwork.', 'internal'),
    ('Invoice issued by Lumen to Harbourbean: SGD 3,000 UNPAID.', 'internal'),
    ('Supplier list: orders@quickprint.example', 'internal'),
    ('Contract: base fee SGD 4,200.', 'client-confidential'),
    ('Proposal: Ferro fundraising SGD 180,000. Not public; keep quiet.', 'client-confidential'),
    ('Call notes: Harbourbean discussed new artwork.', 'client-confidential'),
    ('Client: Ferro\nBudget SGD 4,200', 'client-confidential'),
    ('Bank account INVALID-BANK-LUMEN', 'regulated'),
    ('Patient ID INVALID-PATIENT-01; medical condition.', 'regulated'),
    ('Cash-flow notes: money owed SGD 8,040.', 'regulated'),
    ('Personal savings SGD 12,400.', 'regulated'),
    ('NRIC INVALID-NRIC-DANIEL', 'regulated'),
    ('Passport INVALID-PASSPORT-01', 'regulated'),
    ('PayNow INVALID-PAYNOW-LUMEN', 'regulated'),
    ('Card number INVALID-CARD-01', 'regulated'),
    ('Home address INVALID-HOME-ADDRESS', 'regulated'),
    ('name,email,phone\nAisha Noor,aisha@ferro.example,INVALID-PHONE-AISHA', 'regulated'),
    ('Name: Aisha Noor\nEmail: aisha@ferro.example\nPhone: +65 8123 4567', 'regulated'),
    ('Aisha Noor +65 8123 4567', 'regulated'),
    ('Harbourbean case study. Client approved for publication. Design SGD 3,000.', 'public'),
    ('Website copy\nWeekly plan\nProposal: not public\nBank account INVALID-BANK', 'regulated'),
])
def test_content(text, level):
    result = classify(text, 'renamed.md')
    assert result['level'] == level
    assert result['legacy_level'] == ('public' if level == 'public' else 'confidential')
    assert result['plain_label'] and result['evidence']
    assert all({'source', 'line', 'text', 'level', 'reason'} <= e.keys()
               for e in result['evidence'])


@pytest.mark.parametrize('header,body,level', [
    ('public', 'Bank account INVALID-BANK', 'regulated'),
    ('regulated', 'Website copy: welcome.', 'regulated'),
    ('internal', 'Contract: agreed fee.', 'client-confidential'),
    ('confidential', 'Published price list: SGD 7,200.', 'client-confidential'),
])
def test_header_disagreement(header, body, level):
    result = classify(f'Sensitivity: {header}\n{body}', 'example.md')
    assert result['level'] == level and result['disagreement']
    assert any(e['line'] == 1 and e['reason'] == 'declared level' for e in result['evidence'])


@pytest.mark.parametrize('text', ['Website copy: Phone +44 20 7946 0958',
                                 'Public case study: unknown payload ZXQ-private-blob'])
def test_public_marker_does_not_cover_unknown_or_foreign_phone(text):
    assert classify(text, 'public.md')['level'] == 'regulated'


def test_declared_cannot_downgrade_and_legacy_preserved():
    assert classify('Bank account INVALID-BANK', declared='public')['level'] == 'regulated'
    assert classify('Website copy: welcome.', declared='confidential')['legacy_level'] == 'confidential'
    assert not classify('Weekly plan: artwork', declared='internal')['disagreement']


def test_attachment_trap_and_provenance():
    result = classify('Supplier email: please see attached.', 'inbox/email.md', attachments=[
        {'filename': 'patients.csv', 'body': 'name,patient_id,condition\nInvented Patient,INVALID-PATIENT-01,medical condition'}])
    assert result['level'] == 'regulated'
    assert any(e['source'] == 'patients.csv' and e['level'] == 'regulated' for e in result['evidence'])
    assert classify('Website copy', attachments=[classify('Bank account INVALID-BANK')])['level'] == 'regulated'


@pytest.mark.parametrize('kwargs', [
    {'text': ''}, {'text': '   '}, {'text': None}, {'text': b'Website copy'},
    {'text': 'Unclear material'}, {'text': 'Website copy', 'filename': 'file.exe'},
    {'text': 'Website copy', 'declared': 'unknown'},
    {'text': 'Website copy', 'attachments': ['unresolved.csv']},
    {'text': 'Website copy', 'attachments': [{}]},
    {'text': 'Website copy', 'attachments': None},
    {'text': 'Website copy', 'filename': None},
    {'text': 'Sensitivity: public'},
])
def test_unknown_fails_closed(kwargs):
    result = classify(**kwargs)
    assert result['level'] == 'regulated' and result['legacy_level'] == 'confidential'


def test_public_approval_does_not_erase_private_lines():
    assert classify('Client approved for publication: case study.\nUnannounced fundraising SGD 180,000.')['level'] == 'client-confidential'
    assert classify('Client approved for publication: case study.\nBank account INVALID-BANK')['level'] == 'regulated'


@pytest.mark.parametrize('text,level', [
    ('Supplier agreement: client fee SGD 4,200.', 'client-confidential'),
    ('Website copy: contract attached with private terms.', 'client-confidential'),
    ('Case study draft, not approved for publication.', 'client-confidential'),
    ('Name: Aisha Noor\ncondition: asthma', 'regulated'),
])
def test_additional_mixed_traps(text, level):
    assert classify(text)['level'] == level


def test_malformed_classified_attachment():
    assert classify('Website copy', attachments=[{'level': 'public', 'evidence': [None]}])['level'] == 'regulated'


def test_evidence_exact_line_and_no_mutation():
    attachment = {'text': 'Bank account INVALID-BANK', 'filename': 'bank.md'}
    result = classify('Website copy\nProposal: confidential fee.', attachments=[attachment])
    assert attachment == {'text': 'Bank account INVALID-BANK', 'filename': 'bank.md'}
    assert any(e['line'] == 2 and e['text'] == 'Proposal: confidential fee.' for e in result['evidence'])
