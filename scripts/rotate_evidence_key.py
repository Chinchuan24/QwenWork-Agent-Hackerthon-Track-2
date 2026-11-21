"""Retired: rewriting evidence invalidates immutable audit and incident receipts.

Retain historical keys in AEGIS_EVIDENCE_KEYRING_FILE outside DATA_DIR, then
select a new current AEGIS_EVIDENCE_KEY or AEGIS_EVIDENCE_KEY_FILE for new
writes only. This script never opens data, reads keys, or changes triggers.
"""
import sys


MESSAGE = "Evidence rewrite rotation is retired; retain old keys externally and select a new current key for new writes only."


def rotate(old_key: str, new_key: str):
    """Refuse the old API before accessing any database or key material."""
    from aegis.evidence import EvidenceKeyError
    raise EvidenceKeyError(MESSAGE)


def main():
    print(MESSAGE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
