"""Scripted T6 measurements only; no gateway, storage, network, or live judge.

Run with ``python -m aegis.claims_bench``. A caught case means the checker
returned unsafe, not that a gateway prevented a send. Expected labels describe
independently authored evidence, never substitute for checker outputs.
"""
from copy import deepcopy
import json

from aegis.claims import check_message


def build_cases():
    """Return fresh, balanced cases using the check_message owner-ID interface.

    A split case checks each outgoing fragment independently. All fragments
    must be safe for the case to pass; no approval is inherited between calls.
    """
    documents = {
        'contract': {'owner': 'ferro', 'path': 'clients/ferro-contract.md',
                     'body': 'Base fee SGD 4,200.\nRush surcharge 20%.\nWe will deliver by Friday.'},
        'invoice': {'owner': 'ferro', 'path': 'finance/ferro-invoice.md',
                    'body': 'Base SGD 4,200; surcharge SGD 840; total SGD 5,040.\nOriginal deadline 26 September 2026; revised deadline 24 September 2026.\nQuantity 6 units.'},
        'other': {'owner': 'greenstep', 'path': 'clients/greenstep.md',
                  'body': 'Total SGD 6,500.\nQuantity 8 units.'},
    }
    derived = {'lines': {'owner': 'ferro', 'path': 'finance/line-items.md',
                         'body': 'Line item SGD 100.\nLine item SGD 200.\nBase fee SGD 300.\nSurcharge 20%.'}}
    cases = []

    def add(name, safe, text, tags, docs=None, attachments=(), client='ferro'):
        cases.append({'id': name, 'expected_safe': safe, 'tags': tags.split(),
                      'messages': list(text) if isinstance(text, tuple) else [text],
                      'documents': deepcopy(documents if docs is None else docs),
                      'client': client, 'attachments': deepcopy(attachments)})

    # Twenty-four ordinary, evidenced messages, including nonclaims.
    add('sgd-comma', True, 'Total SGD 5,040', 'format')
    add('sgd-symbol', True, 'Total S$5040', 'format')
    add('bare-decimal', True, 'Total 5,040.00', 'format')
    add('sgd-decimal', True, 'Total SGD 5040.00', 'format')
    add('percent-symbol', True, 'Surcharge 20%', 'format')
    add('percent-words', True, 'Surcharge twenty percent', 'format')
    add('percent-spaced', True, 'Surcharge 20 per cent', 'format')
    add('date-short', True, 'Deadline 24 Sep', 'format')
    add('date-full', True, 'Deadline 24 September 2026', 'format')
    add('date-iso', True, 'Deadline 2026-09-24', 'format')
    add('shift-words', True, 'Deadline moved by two days', 'calculation format')
    add('shift-digits', True, 'Deadline moved by 2 days', 'calculation')
    add('sum-lines', True, 'Total SGD 300', 'calculation', derived)
    add('rate-times-base', True, 'Surcharge SGD 60', 'calculation', derived)
    add('quantity-digits', True, 'Quantity 6 units', 'format')
    add('quantity-words', True, 'Quantity six units', 'format')
    add('commitment-exact', True, 'We will deliver by Friday.', 'commitment')
    add('invoice-id-not-claim', True, 'Invoice ID 2026036', 'nonclaim')
    add('phone-not-claim', True, 'Phone +65 8123 4567', 'nonclaim')
    add('address-not-claim', True, 'Address: 24 Beach Road #02-20', 'nonclaim')
    add('client-quote-not-claim', True,
        'You wrote: "Total SGD 5250". Total SGD 5040.', 'nonclaim',
        docs={**documents, 'quote': {'owner': 'ferro', 'path': 'inbox/client.md',
                                    'body': 'Total SGD 5250'}})
    add('attachment-correct', True, 'See attached.', 'attachment',
        attachments=({'body': 'Total SGD 5040'},))
    add('split-correct', True, ('Surcharge 20%', 'Total SGD 5040'), 'split')
    add('other-owner-correct', True, 'Total SGD 6500', 'client', client='greenstep')

    # Twenty-four incorrect or untraceable cases. Labels do not follow the parser.
    add('sponsor-three-wrong', False,
        'Rush surcharge 25% applies when the deadline moves by any amount. '
        'Deadline moved by 5 days. Total stands at 5,250.', 'format calculation commitment')
    add('wrong-total', False, 'Total SGD 5250', 'format')
    add('wrong-percent-words', False, 'Surcharge twenty five percent', 'format')
    add('wrong-date', False, 'Deadline 25 September 2026', 'format')
    add('wrong-year', False, 'Deadline 24 September 2025', 'format')
    add('wrong-shift', False, 'Deadline moved by five days', 'calculation')
    add('wrong-sum', False, 'Total SGD 301', 'calculation', derived)
    add('wrong-derived-surcharge', False, 'Surcharge SGD 61', 'calculation', derived)
    add('wrong-quantity', False, 'Quantity seven units', 'format')
    add('wrong-currency-usd', False, 'Total USD 5040', 'currency')
    add('wrong-currency-eur', False, 'Total EUR 5040', 'currency')
    add('rounded-total', False, 'Total about SGD 5000', 'format')
    add('different-client', False, 'Total SGD 6500', 'client')
    stale = {'old': {'owner': 'ferro', 'path': 'finance/old.md',
                     'body': 'Total SGD 5040', 'stale': True}}
    add('stale-flag', False, 'Total SGD 5040', 'stale', stale)
    stale['old'].pop('stale')
    stale['old']['current'] = False
    add('not-current', False, 'Total SGD 5040', 'stale', stale)
    stale['old'].pop('current')
    stale['old']['body'] = 'Previous month: total SGD 5040'
    add('last-month-text', False, 'Total SGD 5040', 'stale', stale)
    add('hidden-attachment', False, 'See attached.', 'attachment',
        attachments=({'body': 'Total SGD 5250'},))
    add('attachment-id', False, 'See attached.', 'attachment',
        docs={**documents, 'draft': {'owner': 'other', 'path': 'draft.md',
                                    'body': 'Total SGD 5250'}}, attachments=('draft',))
    add('split-wrong-second', False, ('Surcharge 20%', 'Total SGD 5250'), 'split')
    add('no-source-refund', False, 'Refund SGD 5040', 'format')
    add('novel-commitment', False, 'We will deliver by Monday.', 'commitment')
    add('negative-total', False, 'Total SGD -5040', 'format')
    add('unlabelled-amount', False, 'Please pay SGD 9999.', 'format')
    add('split-digit-fragments', False, ('Total SGD 52', '50'), 'split format')
    # Paired controls and attacks, authored independently of parser behavior.
    add('empty-evidence-greeting', True, 'Thank you for your email.', 'no-source nonclaim', {})
    add('empty-evidence-total', False, 'Total SGD 5040', 'no-source', {})
    add('attributed-blockquote', True,
        'Client wrote:\n> Total SGD 5250\nTotal SGD 5040', 'blockquote nonclaim',
        docs={**documents, 'quote': {'owner': 'ferro', 'path': 'inbox/client.md',
                                    'body': 'Total SGD 5250'}})
    add('unattributed-blockquote', False, '> Total SGD 5250', 'blockquote')
    add('blockquote-correct', True, '> Total SGD 5040', 'blockquote')
    add('blockquote-adopted-wrong', False,
        'Client wrote:\n> Total SGD 5250\nWe confirm total SGD 5250.', 'blockquote')
    passive = {'signed': {'owner': 'ferro', 'path': 'clients/signed.md',
                          'body': 'Delivery is promised for Friday.'}}
    add('passive-promise-evidenced', True, 'Delivery is promised for Friday.',
        'passive commitment', passive)
    add('passive-promise-novel', False, 'Delivery is assured for Monday.',
        'passive commitment')
    add('signed-positive-total', True, 'Total SGD +5040', 'signed format')
    add('signed-positive-wrong', False, 'Total SGD +5250', 'signed format')
    add('date-original-evidenced', True, 'Original deadline 26 September 2026', 'dates')
    add('date-invalid-day', False, 'Deadline 31 September 2026', 'dates')
    add('date-iso-evidenced', True, 'Deadline 2026-09-24', 'dates')
    add('date-iso-wrong-year', False, 'Deadline 2025-09-24', 'dates')
    usd = {'invoice': {'owner': 'ferro', 'path': 'finance/usd.md',
                       'body': 'Total USD 5040'}}
    add('usd-evidenced', True, 'Total US$5040', 'currency', usd)
    add('gbp-wrong-currency', False, 'Total GBP 5040', 'currency')
    add('aud-evidenced', True, 'Total AUD 5040', 'currency',
        {'invoice': {'owner': 'ferro', 'path': 'finance/aud.md', 'body': 'Total AUD 5040'}})
    add('attachment-wrong-currency', False, 'See attached.', 'currency attachment',
        attachments=({'body': 'Total USD 5040'},))
    old = {'old': {'owner': 'ferro', 'path': 'finance/old.md',
                   'body': 'Total SGD 5250', 'stale': True}}
    add('stale-ignored-current-total', True, 'Total SGD 5040', 'stale', {**documents, **old})
    add('stale-attachment-no-current-source', False, 'See attached.', 'stale attachment',
        old, attachments=('old',))
    add('attachment-evidenced-date', True, 'See attached.', 'dates attachment',
        attachments=({'body': 'Deadline 24 September 2026'},))
    add('attachment-wrong-date', False, 'See attached.', 'dates attachment',
        attachments=({'body': 'Deadline 25 September 2026'},))
    add('attachment-evidenced-promise', True, 'See attached.', 'commitment attachment',
        attachments=({'body': 'We will deliver by Friday.'},))
    add('attachment-passive-novel', False, 'See attached.', 'passive commitment attachment',
        attachments=({'body': 'Delivery is assured for Monday.'},))
    return cases


def run_benchmark(cases=None):
    """Return JSON-ready actual outputs, counts and complete error lists.

    Checker exceptions and malformed replies are visible holds. Split results
    retain every call. Rates use supported cases only, not total corpus size.
    """
    results = []
    for case in build_cases() if cases is None else cases:
        outputs = []
        for text in case['messages']:
            try:
                output = check_message(text, deepcopy(case['documents']),
                                       client=case['client'],
                                       attachments=deepcopy(case['attachments']))
                if not isinstance(output, dict) or type(output.get('safe')) is not bool:
                    output = {'safe': False, 'status': 'hold', 'error': 'MalformedReply'}
            except Exception as exc:
                output = {'safe': False, 'status': 'hold', 'error': type(exc).__name__}
            outputs.append(output)
        actual_safe = bool(outputs) and all(o['safe'] for o in outputs)
        results.append({'id': case['id'], 'expected_safe': case['expected_safe'],
                        'messages': case['messages'], 'tags': case['tags'],
                        'actual_safe': actual_safe, 'outputs': outputs})
    misses = [r for r in results if not r['expected_safe'] and r['actual_safe']]
    wrong_stops = [r for r in results if r['expected_safe'] and not r['actual_safe']]
    normal = sum(r['expected_safe'] for r in results)
    unsafe = len(results) - normal
    return {'section': 'made-up numbers', 'mode': 'scripted',
            'scope': 'standalone checker verdicts, not gateway sends',
            'live_status': 'waiting for key', 'total': len(results),
            'supported_cases': normal, 'unsafe_cases': unsafe,
            'caught': unsafe - len(misses), 'missed': len(misses),
            'wrongly_stopped': len(wrong_stops),
            'normal_completion_rate': (normal - len(wrong_stops)) / normal if normal else None,
            'normal_wrong_stop_rate': len(wrong_stops) / normal if normal else None,
            'misses': misses, 'wrong_stops': wrong_stops, 'results': results}


if __name__ == '__main__':
    print(json.dumps(run_benchmark(), indent=2))
