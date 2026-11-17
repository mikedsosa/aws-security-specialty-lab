"""A small, explicit-subset IAM policy evaluator for study exercises.

This is NOT the AWS policy engine. It evaluates one policy document at a
time and supports only what the lab's own policies use:

* ``Effect``, ``Action``/``NotAction``, ``Resource``/``NotResource``,
  ``Principal`` (``"*"``, ``AWS`` and ``Service``; no ``NotPrincipal``)
* condition operators ``StringEquals``, ``StringNotEquals``, ``StringLike``,
  ``StringNotLike``, ``ArnEquals``, ``ArnNotEquals``, ``ArnLike``,
  ``ArnNotLike``, ``Bool``, ``Null``, each with an optional ``IfExists``
  suffix (``Null`` excepted)
* single-valued context keys only

Anything else (set operators such as ``ForAnyValue:``, numeric or date
operators, policy variables, multi-valued keys) raises ``Unsupported``
instead of guessing. Confirm real decisions with the IAM policy simulator
or IAM Access Analyzer in an account you own.

Missing-key behavior follows the IAM documentation for single-valued keys:
a positive operator is false when the key is absent, a negated operator is
true, ``...IfExists`` is true, and ``Null`` tests presence.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

SUPPORTED_BASE = {
    "StringEquals",
    "StringNotEquals",
    "StringLike",
    "StringNotLike",
    "ArnEquals",
    "ArnNotEquals",
    "ArnLike",
    "ArnNotLike",
    "Bool",
    "Null",
}
NEGATED = {"StringNotEquals", "StringNotLike", "ArnNotEquals", "ArnNotLike"}


class Unsupported(ValueError):
    """Raised for policy grammar this evaluator does not implement."""


@dataclass
class Request:
    action: str
    resource: str = "*"
    context: dict[str, Any] = field(default_factory=dict)
    principal_arn: str | None = None
    principal_service: str | None = None

    def ctx(self, key: str) -> tuple[bool, Any]:
        lowered = {k.lower(): v for k, v in self.context.items()}
        if key.lower() in lowered:
            value = lowered[key.lower()]
            if isinstance(value, (list, tuple, set)):
                raise Unsupported(f"multi-valued context key {key!r}")
            return True, value
        return False, None


@dataclass
class Decision:
    decision: str  # "explicit_deny", "allow" or "no_match"
    matched_allow: list[str]
    matched_deny: list[str]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _glob(pattern: str, value: str, *, case_sensitive: bool) -> bool:
    regex = "^" + "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern) + "$"
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.match(regex, value, flags) is not None


def _arn_like(pattern: str, value: str) -> bool:
    p_parts = pattern.split(":", 5)
    v_parts = value.split(":", 5)
    if len(p_parts) != 6 or len(v_parts) != 6:
        return False
    return all(_glob(p, v, case_sensitive=True) for p, v in zip(p_parts, v_parts, strict=True))


def _compare(base: str, expected: str, actual: Any) -> bool:
    actual_s = str(actual).lower() if isinstance(actual, bool) else str(actual)
    if base in {"StringEquals", "StringNotEquals"}:
        return expected == actual_s
    if base in {"StringLike", "StringNotLike"}:
        return _glob(expected, actual_s, case_sensitive=True)
    if base in {"ArnEquals", "ArnNotEquals"}:
        return expected == actual_s
    if base in {"ArnLike", "ArnNotLike"}:
        return _arn_like(expected, actual_s)
    if base == "Bool":
        return expected.lower() == actual_s.lower()
    raise Unsupported(base)


def _condition_true(operator: str, key: str, values: Any, request: Request) -> bool:
    if ":" in operator and operator.split(":", 1)[0] in {"ForAnyValue", "ForAllValues"}:
        raise Unsupported(f"set operator {operator}")
    if_exists = operator.endswith("IfExists")
    base = operator[: -len("IfExists")] if if_exists else operator
    if base not in SUPPORTED_BASE or (if_exists and base == "Null"):
        raise Unsupported(f"condition operator {operator}")
    expected = [str(v).lower() if isinstance(v, bool) else str(v) for v in _as_list(values)]
    if any("${" in v for v in expected):
        raise Unsupported("policy variables")
    present, actual = request.ctx(key)

    if base == "Null":
        want_absent = [v.lower() == "true" for v in expected]
        return any(w == (not present) for w in want_absent)
    if not present:
        return True if if_exists else base in NEGATED
    matched = any(_compare(base, e, actual) for e in expected)
    return not matched if base in NEGATED else matched


def _conditions_true(conditions: dict[str, Any] | None, request: Request) -> bool:
    for operator, block in (conditions or {}).items():
        if not isinstance(block, dict):
            raise Unsupported("condition block must be an object")
        for key, values in block.items():
            if not _condition_true(operator, key, values, request):
                return False
    return True


def _action_matches(stmt: dict[str, Any], action: str) -> bool:
    if "Action" in stmt:
        return any(_glob(p, action, case_sensitive=False) for p in _as_list(stmt["Action"]))
    if "NotAction" in stmt:
        return not any(_glob(p, action, case_sensitive=False) for p in _as_list(stmt["NotAction"]))
    raise Unsupported("statement without Action or NotAction")


def _resource_matches(stmt: dict[str, Any], resource: str) -> bool:
    if "Resource" in stmt:
        return any(_glob(p, resource, case_sensitive=True) for p in _as_list(stmt["Resource"]))
    if "NotResource" in stmt:
        return not any(_glob(p, resource, case_sensitive=True) for p in _as_list(stmt["NotResource"]))
    # SCPs may omit Resource only when it is "*" implicitly; treat as match-all.
    return True


def _principal_matches(stmt: dict[str, Any], request: Request) -> bool:
    if "NotPrincipal" in stmt:
        raise Unsupported("NotPrincipal")
    if "Principal" not in stmt:
        return True  # identity policy or SCP
    principal = stmt["Principal"]
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        raise Unsupported("Principal form")
    for kind, ids in principal.items():
        for ident in _as_list(ids):
            if kind == "AWS":
                if ident == "*":
                    return True
                if request.principal_arn and fnmatch.fnmatchcase(request.principal_arn, ident):
                    return True
            elif kind == "Service":
                if request.principal_service == ident:
                    return True
            else:
                raise Unsupported(f"Principal type {kind}")
    return False


def evaluate(policy: dict[str, Any], request: Request) -> Decision:
    allow: list[str] = []
    deny: list[str] = []
    for index, stmt in enumerate(_as_list(policy.get("Statement"))):
        sid = stmt.get("Sid", f"#{index}")
        if (
            _principal_matches(stmt, request)
            and _action_matches(stmt, request.action)
            and _resource_matches(stmt, request.resource)
            and _conditions_true(stmt.get("Condition"), request)
        ):
            (deny if stmt.get("Effect") == "Deny" else allow).append(sid)
    if deny:
        return Decision("explicit_deny", allow, deny)
    if allow:
        return Decision("allow", allow, deny)
    return Decision("no_match", allow, deny)
