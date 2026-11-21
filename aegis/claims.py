"""Standalone, deterministic T6 evidence checker. No I/O or key discovery.

Documents are caller-selected evidence snapshots, not instructions. The caller
must supply current, trusted files and enforce R18 on safe=False. Client is an
owner ID (None checks across owners but never combines owners for arithmetic).
Attachments are outgoing text dictionaries or document IDs, not extra proof.
Optional client is NOT a model transport: the `client` argument is the owner ID.
Semantic wording uses an exact-text stand-in; live judging awaits integration
with the shared capped Qwen client. No arbitrary callback can override numbers.
"""
import re
import unicodedata
from collections.abc import Mapping
from datetime import date
from decimal import Decimal

_WORDS = dict(zip('zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty thirty forty fifty sixty seventy eighty ninety'.split(), list(range(21)) + list(range(30, 100, 10))))
_NUM = r'(?:-?\d[\d,]*(?:\.\d+)?|(?:' + '|'.join(_WORDS) + r')(?:[ -](?:' + '|'.join(_WORDS) + r'))?)'
_MONTH = r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)'
_TOKEN = re.compile(r'(?P<date>\b(?:\d{1,2}\s+' + _MONTH + r'(?:\s+\d{4})?|' + _MONTH + r'\s+\d{1,2}(?:,?\s+\d{4})?)\b)|(?P<iso>\b\d{4}-\d{2}-\d{2}\b)|(?P<money>(?:SGD|USD|EUR|GBP|AUD|S\$|US\$|\$)\s*' + _NUM + r')|(?P<percent>' + _NUM + r'\s*(?:%|percent\b|per cent\b))|(?P<count>' + _NUM + r'\s*(?:days?|weeks?|months?|hours?|units?|items?|revisions?|invoices?|actions?|things?)\b)|(?P<number>(?<![\w\d])-?\d[\d,]*(?:\.\d+)?\b(?:\s*(?:SGD|USD|EUR|GBP|AUD)\b)?)', re.I)
_LABEL = re.compile(r'\b(total|base|surcharge|rush|discount|refund|quantity|floor|price|fee|amount|line item|deadline|issued|original|revised|delivery|deposit|balance)\b', re.I)


def _number(raw):
    raw = raw.lower().replace(',', '').strip()
    if re.fullmatch(r'-?\d+(?:\.\d+)?', raw):
        return Decimal(raw)
    return Decimal(sum(_WORDS[w] for w in raw.replace('-', ' ').split()))


def _clean(text):
    text = unicodedata.normalize('NFKC', text)
    # Only clearly attributed quoted spans are exempt, not surrounding text.
    text = re.sub(r'(?:you wrote|you said|client wrote|client said)\s*:\s*"[^"\n]*"', '', text, flags=re.I)
    text = re.sub(r'(?:you wrote|you said|client wrote|client said)\s*:[ \t]*\n(?:[ \t]*>[^\n]*(?:\n|$))+', lambda m: '\n' * m.group().count('\n'), text, flags=re.I)
    # Mask only recognizable identifier spans. Labels never hide the rest of a line.
    text = re.sub(r'\b(?:invoice[ \t]*(?:id|number|no\.?|#))[ \t]*[:#]?[ \t]*(?:INVALID-INVOICE-[\w-]+|[A-Z]*-?\d[\w-]*)\b', '', text, flags=re.I)
    text = re.sub(r'\b(?:phone|telephone)[ \t]*[:#]?[ \t]*\+?\d[\d ()-]{5,}\d', '', text, flags=re.I)
    text = re.sub(r'\baddress[ \t]*:[ \t]*\d+[ \t]+(?:[A-Za-z]+[ \t]+){1,4}(?:Road|Street|Avenue|Lane|Drive|Rd|St)\b(?:[ \t]*#\d+-\d+)?', '', text, flags=re.I)
    return text


def _extract(text):
    result = []
    heading = ''
    for line_no, line in enumerate(_clean(text).splitlines(), 1):
        if line.strip() and not _TOKEN.search(line):
            heading = re.sub(r'\s+', ' ', line.strip(' .:').lower())
        if re.search(r'\b[A-Za-z]+\s+\d{1,2},\s+\d{4}\b', line) and not any(m.lastgroup == 'date' for m in _TOKEN.finditer(line)):
            raise ValueError('Unknown month-first date')
        # Unsupported scales must not disappear or leave a supported partial number.
        if re.search(r'\b(?:hundred|thousand|million|billion|trillion)\b', line, re.I):
            raise ValueError('Unsupported numeric scale')
        for m in _TOKEN.finditer(line):
            raw = m.group()
            before = line[:m.start()]
            labels = list(_LABEL.finditer(before))
            label = labels[-1].group().lower() if labels else ''
            label = {'rush':'surcharge', 'fee':'base', 'amount':'price', 'revised':'deadline', 'delivery':'deadline'}.get(label, label)
            kind = m.lastgroup
            currency = None
            if kind in ('date', 'iso'):
                kind = 'date'
                if m.lastgroup == 'iso':
                    dt = date.fromisoformat(raw)
                    value = (dt.month, dt.day, dt.year)
                else:
                    parts = raw.replace(',', '').split()
                    if parts[0].isalpha():
                        parts[0], parts[1] = parts[1], parts[0]
                    months = 'jan feb mar apr may jun jul aug sep oct nov dec'.split()
                    value = (months.index(parts[1][:3].lower()) + 1, int(parts[0]), int(parts[2]) if len(parts) == 3 else None)
                    date(value[2] or 2026, value[0], value[1])
                # Preserve original dates for derived shifts; outgoing defaults to revised.
                if re.search(r'original\s+(?:deadline\s*)?$', before, re.I):
                    label = 'original'
                elif re.search(r'(?:earlier|later) than\s*$', before, re.I):
                    label = 'cutoff'
                elif label not in ('issued', 'original'):
                    label = 'deadline'
            elif kind == 'money':
                cur = re.match(r'(SGD|USD|EUR|GBP|AUD|S\$|US\$|\$)', raw, re.I).group().upper()
                currency = {'S$':'SGD', 'US$':'USD', '$':'unknown'}.get(cur, cur)
                value = _number(raw[len(cur):])
                kind = 'money'
            elif kind == 'percent':
                value = _number(re.sub(r'\s*(%|percent|per cent)$', '', raw, flags=re.I))
            elif kind == 'count':
                unit = re.search(r'[a-z]+$', raw, re.I).group().lower().rstrip('s')
                value = _number(raw[:raw.lower().rfind(unit)].strip())
                kind = 'duration' if unit in ('day', 'week', 'month', 'hour') else 'quantity'
                label = unit
            else:
                suffix = re.search(r'\s*(SGD|USD|EUR|GBP|AUD)$', raw, re.I)
                currency = suffix.group(1).upper() if suffix else None
                value = _number(raw[:suffix.start()] if suffix else raw)
                kind = 'money' if currency or label in ('total', 'base', 'price', 'surcharge', 'floor', 'refund', 'deposit', 'balance', 'line item') else 'number'
            # Bind this explicit package price to its item, not every price-list amount.
            if kind == 'money' and label in ('', 'price'):
                prefix = re.split(r'[;.!?]', before)[-1].strip()
                suffix = re.split(r'[;.!?]', line[m.end():], maxsplit=1)[0].strip()
                if not suffix and re.fullmatch(
                        r'(?:published price list:\s*|(?:the\s+)?published\s+)?'
                        r'website package\s+(?:is\s+)?', prefix + ' ', re.I):
                    label = 'website package price'
            direction = None
            if kind == 'duration' and re.search(r'\bdeadline\b', line, re.I):
                directions = re.findall(r'\b(earlier|later)\b', line, re.I)
                if len(set(d.lower() for d in directions)) > 1:
                    raise ValueError('Ambiguous deadline direction')
                direction = directions[0].lower() if directions else None
            # Only exact structural prefixes or explicit headings bind operands.
            clause = re.split(r'[;.!?]', before)[-1]
            first_label = _LABEL.search(clause)
            context = clause[:first_label.start()] if first_label else ''
            context = re.sub(r'\s+', ' ', context.strip(' :').lower())
            if context in ('base', 'rush', 'our', 'the', 'per our contract the', '>', 'per contract'):
                context = ''
            if label == 'website package price':
                context = 'website package'
            if label == 'surcharge':
                context = re.sub(r'\brush$', '', context).strip()
            result.append({'claim':raw, 'kind':kind, 'value':value, 'currency':currency,
                           'context': context or (heading if re.search(r'\b(package|service)\b', heading) else ''),
                           'direction':direction,
                           'label':label, 'line':line_no, 'sentence':line})
    return result


def _same(a, b):
    if a['kind'] == 'date':
        return a['value'][:2] == b['value'][:2] and (a['value'][2] is None or a['value'][2] == b['value'][2])
    return (a['value'] == b['value']
            and (a['currency'] is None or a['currency'] == b['currency'])
            and (a.get('direction') is None or a['direction'] == b.get('direction')))


def _display(f):
    if f['kind'] == 'date':
        month, day, year = f['value']
        return f'{day} {"Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()[month-1]}' + (f' {year}' if year else '')
    return (f['currency'] + ' ' if f['currency'] else '') + str(f['value']) + ('%' if f['kind'] == 'percent' else '')


FINANCIAL_TERM_TYPES = frozenset((
    'amount', 'price', 'rate', 'discount', 'refund', 'fee', 'tax', 'currency',
    'quantity_times_price', 'payment_terms', 'due_date', 'payment_date',
    'bank_details', 'account_details', 'credit_limit'))


def compare_financial_terms(proposed, source, binding, *, owner):
    """Compare complete structured snapshots, never infer authority from wording.

    The gateway must authenticate the human agreement receipt and proposal
    binding before calling. Missing keys are removals, not unchanged terms.
    """
    import hashlib
    result = {'status': 'hold', 'safe': False, 'binding': binding,
              'changes': [], 'reason': 'Current agreed authority unavailable.'}
    if not isinstance(source, Mapping) or not isinstance(binding, Mapping):
        return result
    if (source.get('current') is not True or source.get('stale')
            or source.get('owner') != owner or not owner
            or not isinstance(source.get('body'), str)
            or not source.get('version')
            or binding.get('path') != source.get('path')
            or binding.get('version') != source.get('version')
            or binding.get('sha256') != hashlib.sha256(source['body'].encode()).hexdigest()):
        return result
    agreed = source.get('financial_terms')
    if not isinstance(agreed, Mapping) or not isinstance(proposed, Mapping):
        return result
    for terms in (agreed, proposed):
        if any(k not in FINANCIAL_TERM_TYPES or not isinstance(v, str)
               or not v.strip() for k, v in terms.items()):
            return result
    for kind in sorted(set(agreed) | set(proposed)):
        if agreed.get(kind) != proposed.get(kind):
            result['changes'].append({'type': kind, 'operation':
                'added' if kind not in agreed else 'removed' if kind not in proposed else 'changed'})
    if not result['changes']:
        result.update(status='supported', safe=True, reason='Complete terms match current agreement.')
    else:
        result['reason'] = 'Financial terms changed; human review required.'
    return result


def check_message(text, documents, client=None, attachments=()):
    """Return status, safe, claims and honest semantic availability labels.

    Each claim includes status, real_value, file, 1-based source line, working.
    No-source fields are None. Ambiguous/conflicting evidence holds. Evidence
    metadata `stale=True`, `current=False`, or explicit superseded/previous-month
    text is excluded. Freshness beyond these markers is the caller's contract.
    This function is stateless: split messages are checked independently; partial
    claims cannot inherit approval from an earlier message.
    """
    out = {'status':'supported', 'safe':True, 'claims':[],
           'semantic_mode':'stand-in', 'live_status':'waiting for key'}
    def hold(reason):
        out.update(status='hold', safe=False, reason=reason)
        return out
    if not isinstance(text, str) or not isinstance(documents, Mapping) or not isinstance(attachments, (list, tuple)) or (client is not None and not isinstance(client, str)):
        return hold('Invalid checker input.')
    if len(text) > 200000 or any(ord(c) < 32 and c not in '\n\r\t' for c in text):
        return hold('Unreadable or oversized message.')
    try:
        facts = []
        sources = []
        source_facts = []
        for key, doc in documents.items():
            if not isinstance(doc, Mapping) or not all(isinstance(doc.get(k), str) for k in ('body','path','owner')):
                return hold('Invalid evidence document.')
            if len(doc['body']) > 200000:
                return hold('Evidence exceeds checker limit.')
            if client is not None and doc['owner'] != client:
                continue
            if doc.get('stale') or doc.get('current') is False or re.search(r'\b(superseded|previous month|last month|obsolete)\b', doc['body'], re.I):
                continue
            sources.append(doc)
            local = []
            for fact in _extract(doc['body']):
                if doc['path'].startswith('inbox/') and fact['kind'] == 'money':
                    continue
                fact.update(file=doc['path'], owner=doc['owner'], working='')
                facts.append(fact)
                local.append(fact)
            source_facts.append(local)
        # Derived facts stay within a document and owner, with all operand lines.
        for doc, local in zip(sources, source_facts):
            items = [f for f in local if f['kind'] == 'money' and f['label'] == 'line item']
            aggregate = next(((n, line.strip()) for n, line in enumerate(doc['body'].splitlines(), 1)
                              if re.fullmatch(r'\s*sum all line items[.!]?\s*', line, re.I)), None)
            if (items and len({f['currency'] for f in items}) == 1
                    and (len({f['context'] for f in items}) == 1 or aggregate)):
                f = dict(items[0], label='total', value=sum((i['value'] for i in items), Decimal(0)))
                f['working'] = ' + '.join(f"{_display(i)} (line {i['line']})" for i in items)
                if aggregate:
                    f['context'] = ''
                    f['working'] += f'; {aggregate[1]} (line {aggregate[0]})'
                facts.append(f)
            bases = [f for f in local if f['kind'] == 'money' and f['label'] == 'base']
            rates = [f for f in local if f['kind'] == 'percent' and f['label'] == 'surcharge']
            for base in bases:
                for rate in rates:
                    if base['context'] != rate['context']:
                        continue
                    f = dict(base, label='surcharge', value=base['value'] * rate['value'] / 100)
                    f['working'] = f"{_display(base)} (line {base['line']}) * {_display(rate)} (line {rate['line']}) / 100"
                    facts.append(f)
            old = [f for f in local if f['kind'] == 'date' and f['label'] == 'original']
            new = [f for f in local if f['kind'] == 'date' and f['label'] == 'deadline']
            for a in old:
                for b in new:
                    if a['context'] == b['context'] and a['value'][2] and b['value'][2]:
                        av = date(a['value'][2], *a['value'][:2])
                        bv = date(b['value'][2], *b['value'][:2])
                        f = dict(b, kind='duration', label='day', value=Decimal(abs((bv-av).days)),
                                 direction='later' if bv > av else 'earlier' if bv < av else None)
                        f['working'] = f"{_display(a)} (line {a['line']}) to {_display(b)} (line {b['line']}) = {f['value']} days"
                        facts.append(f)
        messages = [text]
        for attachment in attachments:
            doc = documents.get(attachment) if isinstance(attachment, str) else attachment
            if not isinstance(doc, Mapping) or not isinstance(doc.get('body'), str):
                return hold('Attachment cannot be checked.')
            messages.append(doc['body'])
        for message in messages:
            # Subject headings are not package identities. Only explicit
            # structural operand prefixes bind claim contexts.
            if len(message) > 200000:
                return hold('Attachment exceeds checker limit.')
            quote_pattern = r'(?:you wrote|you said|client wrote|client said)\s*:\s*(?:"([^"\n]*)"|[ \t]*\n((?:[ \t]*>[^\n]*(?:\n|$))+))'
            for quote in re.finditer(quote_pattern, unicodedata.normalize('NFKC', message), re.I):
                quoted = quote.group(1) if quote.group(1) is not None else re.sub(r'(?m)^[ \t]*>[ \t]?', '', quote.group(2)).strip()
                found = next(((doc['path'], n) for doc in sources
                              for n, line in enumerate(doc['body'].splitlines(), 1)
                              if quoted.strip() == line.strip()), None)
                out['claims'].append({'claim': quoted, 'status': 'supported' if found else 'no_source',
                                      'real_value': quoted if found else None,
                                      'file': found[0] if found else None, 'line': found[1] if found else None,
                                      'working': 'Exact referenced source quote.' if found else 'Attributed quote lacks source proof.'})
            for claim in _extract(message):
                candidates = [f for f in facts if f['kind'] == claim['kind'] and f['label'] == claim['label']]
                if claim['context']:
                    candidates = [f for f in candidates if f['context'] == claim['context']]
                elif len({(f['owner'], f['context']) for f in candidates}) > 1:
                    candidates = []
                values = {(str(f['value']), f['currency'], f.get('direction')) for f in candidates}
                match = next((f for f in candidates if _same(claim, f)), None)
                status = 'supported' if match else 'contradicted' if candidates else 'no_source'
                if len(values) > 1:
                    status = 'hold'
                if re.search(r'\b(about|approximately|roughly|rounded)\b', claim['sentence'], re.I):
                    status = 'hold'
                chosen = match or (candidates[0] if candidates else None)
                out['claims'].append({'claim':claim['claim'], 'status':status,
                                      'real_value':_display(chosen) if chosen else None,
                                      'file':chosen['file'] if chosen else None,
                                      'line':chosen['line'] if chosen else None,
                                      'working':chosen['working'] if chosen else ''})
            # Exact semantic stand-in never approves a novel promise or condition.
            for sentence in re.split(r'(?<=[.!?])\s+|\n', _clean(message)):
                if not re.search(r'\b(will|guarantee(?:d|s)?|assur(?:e|ed|es|ance)|schedul(?:e|ed|es)|promis(?:e|ed|es)|commit(?:ted|s|ment)?|applies|any amount|whenever|tomorrow|today|tonight)\b', sentence, re.I):
                    continue
                canonical = lambda s: re.sub(r'\s+', ' ', s.strip(' .').lower())
                found = None
                for doc in sources:
                    for n, line in enumerate(doc['body'].splitlines(), 1):
                        if canonical(sentence) in [canonical(s) for s in re.split(r'(?<=[.!?])\s+', line)]:
                            found = (doc['path'], n)
                            break
                    if found:
                        break
                out['claims'].append({'claim':sentence, 'status':'supported' if found else 'hold',
                                      'real_value':sentence if found else None,
                                      'file':found[0] if found else None, 'line':found[1] if found else None,
                                      'working':'Exact wording stand-in; novel wording needs the live judge.'})
        statuses = {c['status'] for c in out['claims']}
        out['status'] = next((s for s in ('contradicted','hold','no_source') if s in statuses), 'supported')
        out['safe'] = out['status'] == 'supported'
        return out
    except Exception:
        return hold('Checker could not establish support.')
