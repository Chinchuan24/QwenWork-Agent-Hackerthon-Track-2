"""Sandbox manifest registry, never live authorization or runtime receipts."""
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json

from .tool_passport import PassportDecision, ToolPassport, manifest_sha256


@dataclass(frozen=True, init=False)
class SandboxToolRegistry:
    """Explicit approval baseline and immutable, deeply detached current snapshot.

    JSON strings retain the full manifests without exposing mutable nested values.
    Reapproval requires constructing a new registry with explicit approved records.
    """
    passport: ToolPassport
    current_records: tuple[tuple[str, str], ...]

    def __init__(self, approved_records: Sequence[Mapping],
                 current_records: Sequence[Mapping]):
        passport = ToolPassport(approved_records)
        if (not isinstance(current_records, Sequence)
                or isinstance(current_records, (str, bytes, bytearray))):
            raise ValueError("current records must be a sequence of manifests")
        snapshot = []
        names = set()
        for record in current_records:
            manifest_sha256(record)
            name = record["name"]
            if name in names:
                raise ValueError("duplicate current tool name")
            names.add(name)
            snapshot.append((name, json.dumps(
                record, ensure_ascii=False, allow_nan=False)))
        object.__setattr__(self, "passport", passport)
        object.__setattr__(self, "current_records", tuple(snapshot))

    @classmethod
    def from_tool_schemas(cls, *, approved_records: Sequence[Mapping],
                          tool_schemas: Sequence[Mapping]):
        """Adapt exact OpenAI function fields; refuse anything left unhashed."""
        if (not isinstance(tool_schemas, Sequence)
                or isinstance(tool_schemas, (str, bytes, bytearray))):
            raise ValueError("tool schemas must be a sequence")
        records = []
        for schema in tool_schemas:
            if (type(schema) is not dict or set(schema) != {"type", "function"}
                    or schema["type"] != "function"):
                raise ValueError("tool schema requires type=function and function only")
            function = schema["function"]
            if (type(function) is not dict
                    or set(function) != {"name", "description", "parameters"}):
                raise ValueError("function requires name, description, parameters only")
            records.append({"name": function["name"],
                            "description": function["description"],
                            "input_schema": function["parameters"]})
        return cls(approved_records, records)

    def check_tool(self, name: str) -> PassportDecision:
        """Resolve only the captured candidate; unknown and missing fail closed."""
        if type(name) is not str or not name.strip():
            return PassportDecision("block", "unknown_tool", None)
        for current_name, encoded in self.current_records:
            if current_name == name:
                return self.passport.check(json.loads(encoded))
        reason = "missing_tool" if name in dict(self.passport.approved) else "unknown_tool"
        return PassportDecision("block", reason, None)

    def proof_rows(self) -> list[dict]:
        """Return sandbox comparison rows, not execution evidence."""
        approved = dict(self.passport.approved)
        names = set(approved) | {name for name, _ in self.current_records}
        rows = []
        for name in sorted(names):
            decision = self.check_tool(name)
            rows.append({"name": name, "candidate_sha256": decision.sha256,
                         "approved_sha256": approved.get(name),
                         "status": decision.status, "reason": decision.reason,
                         "scope": "sandbox-only", "gateway_enforced": False,
                         "notice": decision.notice})
        return rows
