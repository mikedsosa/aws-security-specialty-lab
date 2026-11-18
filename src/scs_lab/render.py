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
EXAMPLE_ACCESS_LOGS_BUCKET = "scs-lab-org-trail-access-logs-111122223333"
EXAMPLE_REPLICA_BUCKET = "scs-lab-org-trail-replica-111122223333"
EXAMPLE_REPLICA_ACCESS_LOGS_BUCKET = "scs-lab-org-trail-replica-access-logs-111122223333"
EXAMPLE_REPLICATION_ROLE = "arn:aws:iam::111122223333:role/scs-lab-s3-replication"
EXAMPLE_LOG_GROUP_ARN = "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/scs-lab-remediate-s3-bpa"
EXAMPLE_CLOUDTRAIL_KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000001"
EXAMPLE_REPLICA_KEY_ARN = "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000002"

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
        "replication_role_arn": EXAMPLE_REPLICATION_ROLE,
    },
    "kms-lab-logs-key-policy": {
        "key_admin_arns": [
            "arn:aws:iam::111122223333:role/KeyAdmin",
            "arn:aws:iam::111122223333:role/TerraformDeployer",
        ],
        "region": EXAMPLE["region"],
        "management_account_id": EXAMPLE["management_account_id"],
        "log_group_arn": EXAMPLE_LOG_GROUP_ARN,
    },
    "kms-lab-logs-replica-key-policy": {
        "key_admin_arns": [
            "arn:aws:iam::111122223333:role/KeyAdmin",
            "arn:aws:iam::111122223333:role/TerraformDeployer",
        ],
        "replica_region": "us-west-2",
        "replication_role_arn": EXAMPLE_REPLICATION_ROLE,
        "log_reader_arn": EXAMPLE_LOG_READER,
    },
    "s3-access-logs-bucket-policy": {
        "bucket_name": EXAMPLE_ACCESS_LOGS_BUCKET,
        "trail_bucket_name": EXAMPLE_BUCKET,
        "management_account_id": EXAMPLE["management_account_id"],
        "log_reader_arn": EXAMPLE_LOG_READER,
    },
    "s3-replica-access-logs-bucket-policy": {
        "bucket_name": EXAMPLE_REPLICA_ACCESS_LOGS_BUCKET,
        "source_bucket_name": EXAMPLE_REPLICA_BUCKET,
        "management_account_id": EXAMPLE["management_account_id"],
        "log_reader_arn": EXAMPLE_LOG_READER,
    },
    "s3-trail-replica-bucket-policy": {
        "bucket_name": EXAMPLE_REPLICA_BUCKET,
        "replication_role_arn": EXAMPLE_REPLICATION_ROLE,
        "management_account_id": EXAMPLE["management_account_id"],
        "log_reader_arn": EXAMPLE_LOG_READER,
    },
    "iam-s3-replication": {
        "source_bucket_name": EXAMPLE_BUCKET,
        "destination_bucket_name": EXAMPLE_REPLICA_BUCKET,
        "source_key_arn": EXAMPLE_CLOUDTRAIL_KEY_ARN,
        "destination_key_arn": EXAMPLE_REPLICA_KEY_ARN,
        "region": EXAMPLE["region"],
        "replica_region": "us-west-2",
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
