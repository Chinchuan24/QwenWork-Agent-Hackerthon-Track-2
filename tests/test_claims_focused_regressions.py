"""Focused standalone claim-checker regressions."""
import pytest
from aegis.claims import check_message


def evidence(body):
    return {'a': {'path': 'terms.md', 'owner': 'firm', 'body': body}}


@pytest.mark.parametrize('direction', ['earlier', 'later', 'by'])
def test_opposite_directions_conflict(direction):
    docs = evidence('Deadline moved 2 days earlier.')
    docs['b'] = dict(docs['a'], path='other.md', body='Deadline moved 2 days later.')
    result = check_message(f'Deadline moved {direction} 2 days.', docs)
    assert result['status'] == 'hold', result


@pytest.mark.parametrize('prefix', ['Invoice ID', 'Invoice\nID', 'Phone:', 'Address:'])
def test_label_cannot_hide_next_line(prefix):
    result = check_message(prefix + '\n99999999', {})
    assert not result['safe'], result
    assert result['claims']


@pytest.mark.parametrize('identifier', ['Invoice ID\n12345', 'Phone:\n+65 8123 4567', 'Address: 24\nBeach Road'])
def test_mask_preserves_source_line(identifier):
    result = check_message('Total SGD 100.', evidence(identifier + '\nTotal SGD 100.'))
    assert result['safe'], result
    assert result['claims'][0]['line'] == 3


@pytest.mark.parametrize('body,text', [
    ('Website package base SGD 100.\nDesign package surcharge 20%.', 'Surcharge SGD 20.'),
    ('Website package line item SGD 100.\nDesign package line item SGD 200.', 'Total SGD 300.'),
    ('Website package\nBase SGD 100.\nDesign package\nSurcharge 20%.', 'Surcharge SGD 20.'),
])
def test_unrelated_package_arithmetic(body, text):
    assert not check_message(text, evidence(body))['safe']


@pytest.mark.parametrize('prefix', ['', 'Website package\n'])
def test_legitimate_arithmetic(prefix):
    docs = evidence(prefix + 'Line item SGD 100.\nLine item SGD 200.\nBase SGD 300.\nSurcharge 20%.')
    for text in ('Total SGD 300.', 'Surcharge SGD 60.'):
        result = check_message(text, docs)
        assert result['safe'], result
        assert result['claims'][0]['working']


@pytest.mark.parametrize('body,text', [
    ('Website service base SGD 100.\nDesign service surcharge 20%.', 'Surcharge SGD 20.'),
    ('Website service line item SGD 100.\nDesign service line item SGD 200.', 'Total SGD 300.'),
    ('Website service\nBase SGD 100.\nDesign service\nSurcharge 20%.', 'Surcharge SGD 20.'),
    ('Order Alpha base SGD 100; Order Beta surcharge 20%.', 'Surcharge SGD 20.'),
    ('Website service base SGD 100.\nSurcharge 20%.', 'Surcharge SGD 20.'),
])
def test_unrelated_operand_contexts(body, text):
    result = check_message(text, evidence(body))
    assert not result['safe'], result
    assert all(c['status'] != 'supported' for c in result['claims']), result


@pytest.mark.parametrize('body,text', [
    ('Website service base SGD 125.\nWebsite service surcharge 12%.', 'Surcharge SGD 15.'),
    ('Order Alpha\nBase SGD 125.\nSurcharge 12%.', 'Surcharge SGD 15.'),
    ('Website service line item SGD 125.\nWebsite service line item SGD 175.', 'Total SGD 300.'),
    ('Website service line item SGD 125.\nDesign service line item SGD 175.\nSum all line items.', 'Total SGD 300.'),
])
def test_explicit_operand_context_support(body, text):
    result = check_message(text, evidence(body))
    assert result['safe'], result
    claim = result['claims'][0]
    assert claim['file'] == 'terms.md'
    assert claim['working']
    assert '(line ' in claim['working']


@pytest.mark.parametrize('body,text', [
    ('Alpha price SGD 100.', 'Beta price SGD 100.'),
    ('Alpha original deadline 24 September 2026.\nBeta revised deadline 26 September 2026.', 'Deadline moved 2 days later.'),
    ('Deadline September 24, 2026.', 'Deadline October 24, 2026.'),
    ('Deadline Septober 24, 2026.', 'Deadline October 24, 2026.'),
    ('', 'You said: "I guarantee delivery tomorrow."'),
])
def test_section7_unsupported(body, text):
    assert not check_message(text, evidence(body))['safe']


def test_exact_context_disambiguates_equal_labels():
    result = check_message('Alpha price SGD 100.', evidence('Alpha price SGD 100.\nBeta price SGD 200.'))
    assert result['safe'], result


def test_generic_unique_context_and_paired_dates():
    docs = evidence('Alpha original deadline September 24, 2026.\nAlpha revised deadline September 26, 2026.')
    assert check_message('Deadline moved 2 days later.', docs)['safe']
    assert check_message('Deadline September 26, 2026.', docs)['safe']


def test_aggregate_working_includes_directive():
    result = check_message('Total SGD 300.', evidence('Alpha line item SGD 100.\nBeta line item SGD 200.\nSum all line items.'))
    assert result['safe'], result
    assert 'Sum all line items. (line 3)' in result['claims'][0]['working']


def test_referenced_quote_requires_and_reports_source():
    result = check_message('You said: "I guarantee delivery tomorrow."', evidence('I guarantee delivery tomorrow.'))
    assert result['safe'], result
    assert result['claims'][0]['file'] == 'terms.md'
    assert result['claims'][0]['line'] == 1
