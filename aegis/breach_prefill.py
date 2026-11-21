"""Pure PDPC facts projection; callers supply an already verified incident.

This does not verify receipts, parse narrative text, determine thresholds, or send
notifications. Steps are consumed in the store's append order, never date order.
"""
import json
from collections.abc import Mapping


def pdpc_fact_prefill(verified_incident):
    """Return count/data/harm with unknowns as ''. Copy category containers.

    Only nested ``facts`` fields from the incident and its steps are considered.
    Latest explicit non-None values win independently for each field. Absent
    fields and None mean unknown/no update. Explicit empty or malformed values
    blank that field rather than falling back to stale facts; they do not raise.
    Count remains an integer, harm a boolean, and data text or a fresh list.
    """
    result = {'count': '', 'data': '', 'harm': ''}
    if not isinstance(verified_incident, Mapping):
        return result
    steps = verified_incident.get('steps')
    rows = [verified_incident]
    if isinstance(steps, (list, tuple)):
        rows.extend(steps)
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        facts = row.get('facts')
        if not isinstance(facts, Mapping):
            continue
        for field in result:
            if field in facts and facts[field] is not None:
                result[field] = ''
        count = facts.get('count')
        if type(count) is int and 0 <= count <= 2**63 - 1:
            result['count'] = count
        harm = facts.get('harm')
        if type(harm) is bool:
            result['harm'] = harm
        data = facts.get('data')
        if isinstance(data, str):
            valid = bool(data.strip())
        elif isinstance(data, (list, tuple)):
            valid = bool(data) and all(isinstance(v, str) and v.strip() for v in data)
        else:
            valid = False
        if valid and len(json.dumps(data, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':'))) <= 10000:
            result['data'] = data if isinstance(data, str) else list(data)
    return result
