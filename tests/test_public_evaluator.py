from aegis.public_evaluator import evaluate


def test_amount_and_text_change_verdict():
    low = evaluate('greenstep', 'Price SGD 5,800')
    assert low['decision'] == 'block' and 'R08' in low['rules']
    high = evaluate('greenstep', 'Price SGD 7,200')
    assert high['decision'] != 'block' and 'R08' not in high['rules']
    assert evaluate('harbourbean', 'Public case study approved for publication')['decision'] == 'allow'
    changed = evaluate('harbourbean', 'Public case study. Bank account INVALID-BANK-01')
    assert changed['decision'] != 'allow'
    assert changed['level'] == 'regulated'
    assert low['sources'] and low['semantic_mode'] == 'stand-in'


def test_claim_citations():
    result = evaluate('greenstep', 'Floor SGD 6,500')
    assert any(c['file'] and c['line'] for c in result['claims'])
