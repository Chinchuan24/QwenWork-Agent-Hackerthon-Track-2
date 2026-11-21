"""C5 read-only research catalog. No enforcement, routes or coverage guesses."""
from copy import deepcopy

NOTICE = ('This table shows how Aegis helps you meet rules. '
          'It is not legal advice or a certification.')
READ_DATE = '2026-11-18'
SOURCES = {
    'PDPA': {
        'name': 'Personal Data Protection Act',
        'url': 'https://www.pdpc.gov.sg/organisations/e-services/report-your-organisations-data-breach',
        'version': 'Act revision not verified; guidance dated 22 Apr 2026',
        'publication_status': 'Law; guidance page read',
        'note': 'Page headings readable. Detailed deadline trigger and 500-person threshold were not readable; do not infer them from search hits.'},
    'IMDA agent framework': {
        'name': 'Model AI Governance Framework for Agentic AI',
        'url': 'https://www.imda.gov.sg/resources/press-releases-factsheets-and-speeches/updated-model-ai-governance-framework-for-agentic-ai',
        'version': 'not verified', 'publication_status': 'not verified',
        'note': 'Official update page dated 20 May 2026, updated 21 May 2026. Body not readable. Official PDF returned binary rather than readable text. Do not assume the January edition is current.'},
    'CSA agent guide': {
        'name': 'Securing Agentic AI: An Addendum to the Guidelines and Companion Guide on Securing AI Systems',
        'url': 'https://www.csa.gov.sg/resources/publications/addendum-on-securing-ai-systems/',
        'version': 'June 2026 publication page; document version not verified',
        'publication_status': 'not verified',
        'note': 'Page dated 17 June 2026 still says for public consultation, but says consultation ran 22 October to 31 December 2025 and links a differently named PDF. Final versus draft not settled by this page.'},
    'OWASP agent list': {
        'name': 'OWASP Top 10 for Agentic Applications 2026',
        'url': 'https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/',
        'version': '2026 edition', 'publication_status': 'Released 9 December 2025',
        'note': 'All ten identifiers and names read in the official release announcement. Threats and Mitigations 1.1 is a separate taxonomy, not this list version.'},
}

# Candidate controls are leads for review, not evidence of coverage.
_RISKS = (
    ('Agent Goal Hijack', 'Stop outside text from changing the assigned job.', 'Exposed-session containment'),
    ('Tool Misuse', 'Limit harmful use of otherwise legitimate tools.', 'Tool limits and human holds'),
    ('Identity & Privilege Abuse', 'Keep each helper inside its own permissions.', 'Task limits and helper cards'),
    ('Agentic Supply Chain Vulnerabilities', 'Check dependencies and runtime components for tampering.', 'No verified mapping'),
    ('Unexpected Code Execution', 'Prevent unplanned code from running.', 'No verified mapping'),
    ('Memory & Context Poisoning', 'Keep stored context from redirecting future work.', 'No verified mapping'),
    ('Insecure Inter-Agent Communication', 'Protect messages passed between helpers.', 'No verified mapping'),
    ('Cascading Failures', 'Contain errors before they spread to other actions.', 'Fail-closed checks'),
    ('Human-Agent Trust Exploitation', 'Give people evidence instead of persuasive claims.', 'Approval evidence and claim checker'),
    ('Rogue Agents', 'Stop helpers that act outside their assigned purpose.', 'Freeze and stop controls'),
)


def rule_match_table(*, unreadable_sources=()):
    """Return independent rows for screen/pack consumers, with all gaps visible.

    No stored executed-test receipt has been validated here. Therefore candidate
    controls never raise coverage. Source read failures take precedence.
    """
    rows = []
    for i, (heading, summary, check) in enumerate(_RISKS, 1):
        rows.append({'source': 'OWASP agent list', 'number': f'ASI{i:02}',
                     'heading': heading, 'summary': summary, 'check': check,
                     'source_verified': True})
    for heading, summary in (
        ('Step 1: Assess Whether the Breach is Notifiable', 'Assess whether a personal-data breach needs notification.'),
        ('Step 2: Notify the PDPC and Affected Individuals', 'Notify the required parties after assessing the breach.'),
        ('Step 3: Beyond Reporting the Breach', 'Review what to do after reporting a breach.'),
    ):
        rows.append({'source': 'PDPA', 'number': '', 'heading': heading,
                     'summary': summary, 'check': 'Incident reminder; no verified mapping',
                     'source_verified': True})
    for source in ('IMDA agent framework', 'CSA agent guide'):
        rows.append({'source': source, 'number': '', 'heading': SOURCES[source]['name'],
                     'summary': 'Exact document requirements await readable source verification.',
                     'check': 'No verified mapping', 'source_verified': False})
    for row in rows:
        metadata = SOURCES[row['source']]
        row['source_verified'] = row['source_verified'] and row['source'] not in unreadable_sources
        row.update(url=metadata['url'], read_date=READ_DATE, version=metadata['version'],
                   publication_status=metadata['publication_status'], proof=[],
                   status='not covered' if row['source_verified'] else 'not verified',
                   limitation='No executed proof receipt validated. Candidate check is not a coverage claim.')
    return deepcopy(rows)
