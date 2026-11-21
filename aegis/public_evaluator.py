"""Safe public adapter to the actual deterministic Lumen policy and checkers.

Fixture evidence is invented. No dispatch, database, model or network imports.
"""
from .claims import check_message
from .policy import evaluate_lumen
from .sensitivity import classify

# Bounded fixture excerpts from lumen_world._seed; never expected verdicts.
CASES = {
    'greenstep': {'tool': 'send_email', 'text': 'Price SGD 5,800',
                 'path': 'clients/proposal_greenstep_tuition.md', 'level': 'client-confidential',
                 'body': 'Website proposal SGD 7,200. Do not go below SGD 6,500. Owner floor: SGD 6,500.'},
    'ferro': {'tool': 'accept_terms', 'text': 'Accept settlement SGD 4,200',
              'path': 'clients/contract_ferro_logistics_2026.md', 'level': 'client-confidential',
              'body': 'Base fee SGD 4,200. Any reduced payment, fee waiver or change needs owner approval.'},
    'quickprint': {'tool': 'order_supplier', 'text': 'Reprint 6 units for SGD 720',
                  'path': 'notes/2026-11-16_weekly_plan.md', 'level': 'internal',
                  'body': 'QuickPrint reprint: 6 units for SGD 720, only if Daniel confirms in writing. No written confirmation yet.'},
    'audience': {'tool': 'upload_file', 'text': 'name,email,phone\nInvented Person,person@lumen.example,INVALID-PHONE-01',
                 'path': 'admin/client_list.README.md', 'level': 'regulated',
                 'body': 'Regulated: client_list.csv holds names, emails and phone identifiers. Never upload it to an outside tool.'},
    'harbourbean': {'tool': 'send_email', 'text': 'Public case study approved for publication',
                   'path': 'marketing/case_study_harbourbean.md', 'level': 'public',
                   'body': 'Public case study approved for publication'},
}


def evaluate(case, text=None):
    source = CASES[case]
    text = source['text'] if text is None else text
    doc = {'body': source['body'], 'path': source['path'], 'owner': case}
    checked = check_message(text, {source['path']: doc}, client=case)
    label = classify(text, declared=source['level'])
    result = evaluate_lumen(source['tool'], {'body': text}, client=case,
                            level=label['level'], recipient_known=True,
                            claims_safe=checked['safe'], claims_status=checked['status'])
    result.update(claims=checked['claims'], semantic_mode=checked['semantic_mode'],
                  simulated=True, outside_effects=0,
                  sources=[{'path': source['path'], 'line': 1, 'text': source['body']}])
    return result
