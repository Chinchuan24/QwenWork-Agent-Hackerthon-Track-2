"""Scripted standalone T6 checks, with no live calls."""
import pytest
from aegis.claims import check_message


def test_derived_operands_cannot_cross_snapshot_or_owner():
    documents = {
        'a': {'path': 'shared.md', 'owner': 'ferro',
              'body': 'Line item SGD 100.\nBase fee SGD 100.'},
        'b': {'path': 'shared.md', 'owner': 'other',
              'body': 'Line item SGD 200.\nRush surcharge 20%.'},
    }
    result = check_message('Total SGD 300. Surcharge SGD 20.', documents)
    assert not result['safe']
    assert all(c['status'] != 'supported' for c in result['claims'])
    documents['b']['owner'] = 'ferro'
    assert not check_message('Total SGD 300. Surcharge SGD 20.', documents)['safe']


def test_derived_working_binds_actual_operand_lines():
    documents = {'a': {'path': 'invoice.md', 'owner': 'ferro',
                      'body': 'Invoice details\nLine item SGD 100.\nLine item SGD 200.'}}
    result = check_message('Total SGD 300.', documents, 'ferro')
    assert result['safe']
    assert result['claims'][0]['file'] == 'invoice.md'
    assert result['claims'][0]['line'] == 2
    assert result['claims'][0]['working'] == 'SGD 100 (line 2) + SGD 200 (line 3)'


def test_published_website_package_price_from_real_n11_source():
    from aegis.lumen_normal import CASES
    from aegis.lumen_world import fresh

    case = next(case for case in CASES if case['id'] == 'N11')
    path = case['needed_files'][0]
    result = check_message(case['actions'][-1]['args']['body'], {path: fresh().doc(path)})
    assert result['safe'], result
    assert result['claims'] == [{
        'claim': 'SGD 7,200', 'status': 'supported', 'real_value': 'SGD 7200',
        'file': path, 'line': 1, 'working': '',
    }]


@pytest.mark.parametrize('text', [
    'The published website package is SGD 3,000.',
    'The published design package is SGD 7,200.',
    'The published website package is USD 7,200.',
    'The published website package is SGD 7,200 per unit.',
    'The published website package is SGD 7,200 per month.',
    'The published website package is SGD 7,200 annually.',
    'Refund SGD 7,200.',
    'Total SGD 7,200.',
])
def test_published_package_price_preserves_boundaries(text):
    from aegis.lumen_world import fresh

    path = 'marketing/price_list.md'
    result = check_message(text, {path: fresh().doc(path)})
    assert not result['safe'], result


@pytest.mark.parametrize('body', [
    'Published price list: design package SGD 7,200.',
    'Published price list: website package USD 7,200.',
    'Published price list: website package SGD 3,000.',
    'Published price list: website package SGD 7,200 per unit.',
    'Published price list: website package SGD 7,200 per month.',
    'Published price list: website package SGD 7,200 annually.',
    'Refund: website package SGD 7,200.',
])
def test_website_package_requires_matching_price_source(body):
    result = check_message('The published website package is SGD 7,200.', {
        'p': {'path': 'prices.md', 'owner': 'firm', 'body': body},
    })
    assert not result['safe'], result

@pytest.fixture
def docs():
    return {
        'c': {'path': 'contract.md', 'owner': 'ferro', 'body': 'Base fee SGD 4,200.\nRush surcharge 20% applies if the deadline moves earlier than 30 September 2026.'},
        'i': {'path': 'invoice.md', 'owner': 'ferro', 'body': 'Base SGD 4,200; surcharge SGD 840; total SGD 5,040.\nOriginal deadline 26 September 2026; revised deadline 24 September 2026.\nQuantity 6 units.\nWe will deliver by Friday.'}}

@pytest.mark.parametrize('text', ['Total SGD 5,040','Total S$5040','Total 5,040.00','Total SGD 5040.00','Surcharge 20%','Surcharge twenty percent','Surcharge 20 percent','Deadline 24 Sep','Deadline 24 Sept','Deadline 24 September 2026','Deadline moved by two days','Deadline moved by 2 days','Quantity 6 units','Quantity six units','We will deliver by Friday.','Base fee SGD 4200','Surcharge SGD 840','Hello, thank you.','Invoice ID 2026036','Phone +65 8123 4567','Address: 24 Beach Road #02-20'])
def test_correct(text, docs):
    assert check_message(text, docs, 'ferro')['safe']

@pytest.mark.parametrize('text', ['Total SGD 5250','Total USD 5040','Total EUR 5040','Total SGD 5000','Surcharge 25%','Surcharge twenty five percent','Surcharge 21 percent','Deadline 25 Sep','Deadline 24 September 2025','Deadline moved by 5 days','Quantity 7 units','Quantity seven units','We will deliver by Monday.','Base fee SGD 4300','Surcharge SGD 850','Discount 10%','We guarantee unlimited revisions.','Total about SGD 5040','The deadline moves by any amount.','Refund SGD 5040'])
def test_unsafe(text, docs):
    assert not check_message(text, docs, 'ferro')['safe']

@pytest.mark.parametrize('text', [
    'Total -5040',
    'Total 5040 USD',
    'Total SGD 5040 thousand',
    'Total five thousand two hundred fifty',
    'Surcharge one hundred twenty percent',
    'Deadline moved 2 days later',
])
def test_numeric_and_direction_regressions(text, docs):
    result = check_message(text, docs, 'ferro')
    assert not result['safe'], result
    assert result['status'] in ('contradicted', 'hold', 'no_source'), result


@pytest.mark.parametrize('text', [
    'Total 5040 SGD',
    'Deadline moved 2 days earlier',
    'Deadline moved earlier by two days',
])
def test_supported_suffix_and_direction(text, docs):
    result = check_message(text, docs, 'ferro')
    assert result['safe'], result
    assert result['claims'], result


def test_later_shift_does_not_support_earlier():
    documents = {'i': {'path': 'invoice.md', 'owner': 'ferro', 'body':
        'Original deadline 24 September 2026; revised deadline 26 September 2026.'}}
    result = check_message('Deadline moved 2 days earlier', documents, 'ferro')
    assert not result['safe'], result
    assert check_message('Deadline moved 2 days later', documents, 'ferro')['safe']
    assert check_message('Deadline moved by 2 days', documents, 'ferro')['safe']


def test_s4(docs):
    r = check_message('Rush surcharge 25% applies when the deadline moves by any amount. Deadline moved by 5 days. Total stands at 5,250.', docs, 'ferro')
    assert not r['safe']
    for fragment, value, path in [('25%', '20', 'contract.md'), ('5 days', '2', 'invoice.md'), ('5,250', '5040', 'invoice.md')]:
        c = next(c for c in r['claims'] if fragment in c['claim'])
        assert value in str(c['real_value'])
        assert c['file'] == path and c['line'] > 0

def test_scope(docs):
    assert not check_message('Total SGD 5040', docs, 'other')['safe']
    docs['i']['body'] = 'Previous month, superseded: total SGD 5040.'
    assert not check_message('Total SGD 5040', docs, 'ferro')['safe']

def test_working():
    d = {'i': {'path':'i','owner':'x','body':'Line item SGD 100.\nLine item SGD 200.\nBase fee SGD 300.\nSurcharge 20%.'}}
    for text in ['Total SGD 300', 'Surcharge SGD 60']:
        r = check_message(text, d, 'x')
        assert r['safe'], r
        assert any(c['working'] for c in r['claims'])

def test_quotes(docs):
    assert not check_message('You wrote: "Total SGD 5250". Total SGD 5040.', docs, 'ferro')['safe']
    assert not check_message('You wrote: "Total SGD 5250". Total SGD 5250.', docs, 'ferro')['safe']

def test_attachment_split(docs):
    assert not check_message('See attached.', docs, 'ferro', attachments=({'body':'Total SGD 5250','path':'draft'},))['safe']
    assert not check_message('See attached.', docs, 'ferro', attachments=('missing',))['safe']
    for text in ['Surcharge 25%', 'Total SGD 5250']:
        assert not check_message(text, docs, 'ferro')['safe']

@pytest.mark.parametrize('text,d', [(None, {}), ('x', None), ('x', {'bad':{}})])
def test_invalid(text,d):
    assert check_message(text,d)['status'] == 'hold'

def test_conflict(docs):
    docs['other'] = {'path':'other','owner':'ferro','body':'Total SGD 5250.'}
    assert not check_message('Total SGD 5040',docs,'ferro')['safe']

@pytest.mark.parametrize('text', [
    '> Total SGD 9999',
    'Phone: Total SGD 9999',
    'Address: Total SGD 9999',
    'Invoice ID: Total SGD 9999',
    'Phone: +65 8123 4567 Total SGD 9999',
    'Invoice ID 2026036 Total SGD 9999',
    'Delivery is guaranteed tomorrow.',
    'Delivery is promised tomorrow.',
    'Delivery is committed for tomorrow.',
    'Delivery tomorrow.',
    '> Delivery is guaranteed tomorrow.',
])
def test_no_source_evasion(text):
    documents = {'i': {'path': 'invoice.md', 'owner': 'ferro', 'body': 'Total SGD 100.'}}
    result = check_message(text, documents, 'ferro')
    assert not result['safe'], result
    assert result['claims'], result

@pytest.mark.parametrize('text', [
    'Client wrote: "Total SGD 9999". Total SGD 100.',
    'You wrote: "Delivery is guaranteed tomorrow." Total SGD 100.',
    'Client said:\n> Total SGD 9999\nTotal SGD 100.',
])
def test_attributed_quotes_without_proof_are_unsupported(text):
    documents = {'i': {'path': 'invoice.md', 'owner': 'ferro', 'body': 'Total SGD 100.'}}
    assert not check_message(text, documents, 'ferro')['safe']

@pytest.mark.parametrize('attachment', [False, True])
@pytest.mark.parametrize('promise', [
    'Delivery is assured for Monday.',
    'Delivery is assured.',
    'Delivery is scheduled for Monday.',
    'We assure delivery for Monday.',
])
def test_assured_commitment_without_source(promise, attachment):
    documents = {'i': {'path': 'invoice.md', 'owner': 'ferro', 'body': 'Total SGD 100.'}}
    result = check_message('See attached.' if attachment else promise, documents, 'ferro',
                           attachments=({'path': 'draft', 'body': promise},) if attachment else ())
    assert not result['safe'], result
    assert any(c['claim'] == promise and c['status'] in ('no_source', 'hold')
               for c in result['claims']), result


def test_assured_commitment_requires_matching_source():
    promise = 'Delivery is assured for Monday.'
    documents = {'i': {'path': 'agreement.md', 'owner': 'ferro', 'body': promise}}
    result = check_message(promise, documents, 'ferro')
    assert result['safe'], result
    assert result['claims'][0]['file'] == 'agreement.md'
    assert result['claims'][0]['line'] == 1
    assert not check_message('Delivery is assured for Tuesday.', documents, 'ferro')['safe']
    assert not check_message('Client wrote: "Delivery is assured for Tuesday."', documents, 'ferro')['safe']


def test_semantic(docs):
    r = check_message('Surcharge applies whenever the date changes.',docs,'ferro')
    assert not r['safe']
    assert r['semantic_mode'] == 'stand-in' and r['live_status'] == 'waiting for key'
    def fail(p):
        raise TimeoutError()
    assert not check_message('We guarantee delivery.',docs,'ferro',fail)['safe']
    assert not check_message('Total SGD 5250',docs,'ferro',lambda p: {'status':'supported'})['safe']
