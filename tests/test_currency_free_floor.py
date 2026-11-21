import pytest

from aegis import policy


@pytest.mark.parametrize('field,text', [
    ('body', 'We can match 5,800.'),
    ('subject', 'Quote: 5,800'),
    ('body', 'Our price is 5,800.'),
])
def test_currency_free_greenstep_offer_blocks(field, text):
    result = policy.evaluate_lumen('send_email', {field: text},
                                   client='greenstep', recipient_known=True)
    assert result['decision'] == 'block'
    assert {'R07', 'R08'} <= set(result['rules'])


@pytest.mark.parametrize('amount,decision,rules', [
    ('6,499', 'block', {'R07', 'R08'}),
    ('6,500', 'hold', {'R07'}),
    ('7,200', 'allow', {'R06'}),
])
def test_currency_free_floor_boundaries(amount, decision, rules):
    result = policy.evaluate_lumen('send_email', {'body': f'Price: {amount}.'},
                                   client='greenstep', recipient_known=True)
    assert result['decision'] == decision
    assert rules <= set(result['rules'])
    assert ('R08' in result['rules']) == (decision == 'block')


@pytest.mark.parametrize('text', [
    'We have 5,800 students.',
    'Quote review on 2026-11-19; attendance 5,800.',
    'Match 5,800 units.',
    'Price review: 5,800 students attended.',
    'Quote: 5,800 kg.',
    'Match 2026-11-19.',
    'We can match 5800.',
])
def test_unrelated_numbers_are_not_prices(text):
    result = policy.evaluate_lumen('send_email', {'body': text},
                                   client='greenstep', recipient_known=True)
    assert not {'R06', 'R07', 'R08'} & set(result['rules'])


@pytest.mark.parametrize('client', [None, 'ferro'])
def test_currency_free_requires_trusted_greenstep_client(client):
    result = policy.evaluate_lumen('send_email', {'subject': 'Greenstep quote',
                                   'body': 'We can match 5,800.'},
                                   client=client, recipient_known=True)
    assert not {'R06', 'R07', 'R08'} & set(result['rules'])
