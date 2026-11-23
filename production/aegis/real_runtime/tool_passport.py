"""Pure sandbox-only manifest comparison, not live tool authorization.

Approved records are supplied explicitly by the caller. No discovery, execution,
registration, persistence, or automatic approval occurs. The existing deterministic
injection detector is a heuristic, not proof that a description is safe.
"""
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math

from . import detectors

NOTICE = "sandbox-only manifest check; not permission to execute a live tool"


def _json_value(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json_value(item)
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    raise ValueError("schema must contain plain finite JSON values")


def manifest_sha256(manifest: Mapping) -> str:
    """Hash exact name/description/input_schema using sorted compact UTF-8 JSON.

    Object key ordering is irrelevant; array order and all string bytes matter.
    Extra fields are refused rather than left outside the approved fingerprint.
    """
    try:
        if type(manifest) is not dict or set(manifest) != {
                "name", "description", "input_schema"}:
            raise ValueError("manifest requires name, description, input_schema only")
        if (type(manifest["name"]) is not str or not manifest["name"].strip()
                or type(manifest["description"]) is not str
                or type(manifest["input_schema"]) is not dict):
            raise ValueError("invalid manifest fields")
        _json_value(manifest["input_schema"])
        encoded = json.dumps(dict(manifest), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
    except (TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid JSON manifest") from exc


@dataclass(frozen=True)
class PassportDecision:
    status: str
    reason: str
    sha256: str | None
    notice: str = NOTICE


@dataclass(frozen=True, init=False)
class ToolPassport:
    """Immutable (name, SHA256) snapshot of explicitly approved records."""
    approved: tuple[tuple[str, str], ...]

    def __init__(self, approved_records: Sequence[Mapping]):
        if (not isinstance(approved_records, Sequence)
                or isinstance(approved_records, (str, bytes, bytearray))):
            raise ValueError("approved records must be a sequence of manifests")
        approved = []
        names = set()
        for record in approved_records:
            digest = manifest_sha256(record)
            name = record["name"]
            if name in names:
                raise ValueError("duplicate approved tool name")
            names.add(name)
            approved.append((name, digest))
        object.__setattr__(self, "approved", tuple(approved))

    def check(self, manifest: Mapping) -> PassportDecision:
        """Fail closed; detected description injection overrides any approval."""
        try:
            digest = manifest_sha256(manifest)
        except ValueError:
            return PassportDecision("block", "invalid_manifest", None)
        if detectors.injection_score(manifest["description"]) > 0:
            return PassportDecision("block", "description_injection", digest)
        baseline = dict(self.approved).get(manifest["name"])
        if baseline is None:
            return PassportDecision("block", "unknown_tool", digest)
        if baseline != digest:
            return PassportDecision("hold", "manifest_changed", digest)
        return PassportDecision("allow", "approved_manifest", digest)
