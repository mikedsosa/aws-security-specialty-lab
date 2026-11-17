"""Render the lab's policy templates without Terraform.

The templates in ``terraform/policies`` use two Terraform template forms
only: ``${name}`` and ``${jsonencode(name)}``. This module supports exactly
those, and fails on anything else, so tests read the same JSON that
``templatefile()`` would produce for the example variables.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "terraform" / "policies"

_TOKEN = re.compile(r"\$\{([^}]*)\}")
_JSONENCODE = re.compile(r"^jsonencode\(([a-z_][a-z0-9_]*)\)$")
_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

# Mirrors terraform/variables.tf defaults and terraform/locals.tf. All
# account and organization IDs are documentation placeholders.
EXAMPLE = {
    "region": "us-east-1",
    "name_prefix": "scs-lab",
    "management_account_id": "111122223333",
    "security_account_id": "444455556666",
    "organization_id": "o-exampleorg1",
    "allowed_regions": ["us-east-1", "us-west-2"],
    "break_glass_role_name": "BreakGlassAdmin",
    "trail_name": "scs-lab-org-trail",
}
EXAMPLE_TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:111122223333:trail/scs-lab-org-trail"
EXAMPLE_LOG_READER = "arn:aws:iam::444455556666:role/SecurityLogReader"
EXAMPLE_BOUNDARY_ARN = "arn:aws:iam::111122223333:policy/scs-lab-workload-boundary"
EXAMPLE_BUCKET = "scs-lab-org-trail-111122223333"

TEMPLATE_VARS: dict[str, dict[str, Any]] = {
    "scp-guardrails": {
        "break_glass_role_name": EXAMPLE["break_glass_role_name"],
        "allowed_regions": EXAMPLE["allowed_regions"],
    },
    "rcp-data-perimeter": {"organization_id": EXAMPLE["organization_id"]},
    "kms-cloudtrail-key-policy": {
        "key_admin_arns": [
            "arn:aws:iam::111122223333:role/KeyAdmin",
            "arn:aws:iam::111122223333:role/TerraformDeployer",
        ],
        "trail_arn": EXAMPLE_TRAIL_ARN,
        "management_account_id": EXAMPLE["management_account_id"],
        "log_reader_arn": EXAMPLE_LOG_READER,
        "region": EXAMPLE["region"],
    },
    "s3-trail-bucket-policy": {
        "bucket_name": EXAMPLE_BUCKET,
        "trail_arn": EXAMPLE_TRAIL_ARN,
        "management_account_id": EXAMPLE["management_account_id"],
        "organization_id": EXAMPLE["organization_id"],
        "log_reader_arn": EXAMPLE_LOG_READER,
    },
    "iam-workload-boundary": {
        "name_prefix": EXAMPLE["name_prefix"],
        "region": EXAMPLE["region"],
        "account_id": EXAMPLE["management_account_id"],
    },
    "iam-role-creator": {
        "account_id": EXAMPLE["management_account_id"],
        "workload_role_path": "/app/",
        "boundary_policy_arn": EXAMPLE_BOUNDARY_ARN,
    },
    "lambda-remediation-role": {
        "account_id": EXAMPLE["management_account_id"],
        "region": EXAMPLE["region"],
        "function_name": "scs-lab-remediate-s3-bpa",
        "dlq_arn": "arn:aws:sqs:us-east-1:111122223333:scs-lab-remediation-dlq",
    },
}


class TemplateError(ValueError):
    pass


def render_text(text: str, variables: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        expr = match.group(1).strip()
        enc = _JSONENCODE.match(expr)
        if enc:
            name = enc.group(1)
            if name not in variables:
                raise TemplateError(f"missing variable {name!r}")
            return json.dumps(variables[name], separators=(",", ":"))
        if _NAME.match(expr):
            if expr not in variables:
                raise TemplateError(f"missing variable {expr!r}")
            value = variables[expr]
            if not isinstance(value, str):
                raise TemplateError(f"{expr!r} is not a string; use jsonencode()")
            return value
        raise TemplateError(f"unsupported template expression ${{{expr}}}")

    return _TOKEN.sub(replace, text)


def render_policy(name: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    path = POLICY_DIR / f"{name}.json.tftpl"
    vars_ = TEMPLATE_VARS[name] if variables is None else variables
    return json.loads(render_text(path.read_text(encoding="utf-8"), vars_))


def render_all(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name in sorted(TEMPLATE_VARS):
        target = out_dir / f"{name}.json"
        target.write_text(json.dumps(render_policy(name), indent=2) + "\n", encoding="utf-8")
        written.append(target)
    return written
