"""Pure, conservative content labels; no file access or permission decisions.

Attachments are text strings only when wrapped in a mapping with text/body,
filename/path, optional declared/sensitivity and nested attachments. A previously
classified result may also be supplied. Bare paths are unresolved, never read.
Evidence contains sensitive source text: callers must mask it on owner screens.
"""
import re
from pathlib import PurePath


LEVELS = ('public', 'internal', 'client-confidential', 'regulated')
LABELS = ('Safe to share', 'For your business only', 'Private client information',
          'Personal, bank or health information')


def classify(text, filename='', attachments=(), declared=None):
    """Return level, legacy_level, evidence, disagreement and plain_label.

    Higher content, declarations and attachments win. Legacy confidential maps
    to client-confidential, and every non-public result stays confidential.
    Empty, unsupported, malformed or unrecognized input becomes regulated.
    Evidence source/line/text identifies the exact input (line 0 is metadata).
    Disagreement is a boolean, comparing declarations with content/attachments.
    """
    evidence = []
    declarations = []
    content_levels = []
    disagreement = False
    source = filename if isinstance(filename, str) and filename else '<text>'

    def add(level, reason, line=0, value=''):
        evidence.append(dict(source=source, line=line, text=value,
                             level=level, reason=reason))
        content_levels.append(level)

    def declaration(value, line=0, raw=''):
        normalized = value.strip().lower().replace('_', '-').replace(' ', '-') if isinstance(value, str) else ''
        if normalized == 'confidential':
            normalized = 'client-confidential'
        if normalized not in LEVELS:
            add('regulated', 'unknown declared level', line, raw)
        else:
            declarations.append(normalized)
            evidence.append(dict(source=source, line=line, text=raw or value,
                                 level=normalized, reason='declared level'))

    if declared is not None:
        declaration(declared)
    if not isinstance(filename, str) or (filename and PurePath(filename).suffix.lower()
                                        not in ('', '.md', '.txt', '.csv', '.json', '.html', '.eml', '.log', '.tsv')):
        add('regulated', 'unsupported file type')
    if not isinstance(text, str) or not text.strip() or '\x00' in text:
        add('regulated', 'empty or unreadable content')
        lines = []
    else:
        lines = text.splitlines()
    body = []
    for number, line in enumerate(lines, 1):
        header = re.match(r'^\s*(?:#+\s*)?(?:sensitivity|classification|data[- ]level)\s*:\s*(.*?)\s*$', line, re.I)
        if header:
            declaration(header[1], number, line)
        else:
            body.append((number, line))
    combined = '\n'.join(line for _, line in body)
    has_client = bool(re.search(r'^\s*client\s*:', combined, re.I | re.M))
    contact_table = bool(re.search(r'\bname\b.*\bemail\b.*\bphone\b', combined, re.I))
    named_contact = bool(re.search(r'\bname\s*:', combined, re.I) or
                         re.search(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b', combined))
    phone = r'(?:\+?65[ -]?)?[689]\d{3}[ -]?\d{4}\b|INVALID-PHONE[\w-]*'
    private = r'\b(?:unannounced|not public|keep quiet|NDA|confidential|private terms|not approved for publication|case study draft|fundraising plans private)\b'
    regulated = (r'\b(?:NRIC|passport|PayNow|bank account|bank details|bank update|card number|'
                 r'credit card|home address|personal savings|cash[- ]?flow|patient|diagnosis|medical condition|'
                 r'health information|condition\s*:)\b|\b[A-Z]\d{7}[A-Z]\b|'
                 r'INVALID-(?:BANK|CARD|NRIC|PASSPORT|PAYNOW|PATIENT|HOME-ADDRESS)[\w-]*')
    for number, line in body:
        if (re.search(r'\b(?:phone|telephone|mobile)\b.*\+?\d[\d ()-]{6,}\d', line, re.I)
                or re.search(r'\b(?:unknown|unrecognized|unverified)\s+(?:payload|content|data)\b', line, re.I)):
            add('regulated', 'unverified content or telephone data', number, line)
        if re.search(regulated, line, re.I):
            add('regulated', 'personal, financial account or health data', number, line)
        if contact_table and line.strip() or (named_contact and re.search(phone, line, re.I)):
            add('regulated', 'identifiable contact details', number, line)
        if re.search(private, line, re.I):
            add('client-confidential', 'private client information', number, line)
        # Publication approval covers this line, never later private lines.
        public = bool(re.search(r'\b(?:website copy|website design|published price list|public case study|case study|'
                                r'approved for publication|marketing email received)\b', line, re.I))
        internal = bool(re.search(r'\b(?:invoice|supplier|weekly plan|to-do|reminder|reprint|floor)\b', line, re.I))
        if not public and re.search(r'\b(?:contract|agreement|proposal|quote|call notes)\b', line, re.I):
            add('client-confidential', 'client agreement or working notes', number, line)
        if has_client and not public and not internal and (re.search(r'^\s*client\s*:', line, re.I) or
                                                         re.search(r'\b(?:SGD|S\$|budget)\b', line, re.I)):
            add('client-confidential', 'named client information', number, line)
        if internal:
            add('internal', 'business working information', number, line)
        if public:
            add('public', 'publication or marketing material', number, line)
    if not content_levels:
        add('regulated', 'unrecognized content')
    if not isinstance(attachments, (tuple, list)):
        add('regulated', 'unreadable attachments')
    else:
        for attachment in attachments:
            if not isinstance(attachment, dict):
                add('regulated', 'unresolved attachment')
                continue
            if 'text' in attachment or 'body' in attachment:
                try:
                    result = classify(attachment.get('text', attachment.get('body')),
                                      attachment.get('filename', attachment.get('path', '')),
                                      attachment.get('attachments', ()),
                                      attachment.get('declared', attachment.get('sensitivity')))
                except (RecursionError, TypeError, ValueError):
                    add('regulated', 'unreadable attachment')
                    continue
            elif (attachment.get('level') in LEVELS and isinstance(attachment.get('evidence'), list)
                  and attachment['evidence']
                  and all(isinstance(e, dict)
                          and {'source', 'line', 'text', 'level', 'reason'} <= e.keys()
                          and isinstance(e['source'], str)
                          and isinstance(e['line'], int) and not isinstance(e['line'], bool)
                          and e['line'] >= 0
                          and isinstance(e['text'], str)
                          and isinstance(e['reason'], str)
                          and e['level'] in LEVELS
                          and LEVELS.index(e['level']) <= LEVELS.index(attachment['level'])
                          for e in attachment['evidence'])):
                result = attachment
            else:
                add('regulated', 'unresolved attachment')
                continue
            content_levels.append(result['level'])
            evidence.extend(dict(e) for e in result['evidence'] if isinstance(e, dict))
            disagreement = disagreement or bool(result.get('disagreement'))
    content = max(content_levels, key=LEVELS.index)
    disagreement = disagreement or any(level != content for level in declarations)
    level = max([content] + declarations, key=LEVELS.index)
    return dict(level=level, legacy_level='public' if level == 'public' else 'confidential',
                evidence=evidence, disagreement=disagreement, plain_label=LABELS[LEVELS.index(level)])
