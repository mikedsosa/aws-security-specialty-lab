"""Checks against build/plan.json from scripts/offline-plan.sh.

Skipped when the plan has not been generated, so `pytest` alone stays
offline and Terraform-free. `make plan test` runs them.
"""

import json

import pytest

from conftest import REPO
from scs_lab.render import render_policy

PLAN = REPO / "build" / "plan.json"

pytestmark = pytest.mark.skipif(not PLAN.exists(), reason="run scripts/offline-plan.sh first")


@pytest.fixture(scope="module")
def resources():
    plan = json.loads(PLAN.read_text())
    return {
        r["address"]: r for r in plan["planned_values"]["root_module"]["resources"] if r["mode"] == "managed"
    }


def values(resources, address):
    return resources[address]["values"]


@pytest.mark.parametrize(
    ("address", "template"),
    [
        ("aws_organizations_policy.guardrails", "scp-guardrails"),
        ("aws_organizations_policy.data_perimeter", "rcp-data-perimeter"),
        ("aws_kms_key.cloudtrail", "kms-cloudtrail-key-policy"),
        ("aws_iam_policy.workload_boundary", "iam-workload-boundary"),
        ("aws_iam_policy.role_creator", "iam-role-creator"),
    ],
)
def test_terraform_renders_the_same_policy_the_tests_check(resources, address, template):
    v = values(resources, address)
    rendered = v.get("content") or v.get("policy")
    assert json.loads(rendered) == render_policy(template)


def test_plan_creates_only_and_has_no_attachments_by_default(resources):
    plan = json.loads(PLAN.read_text())
    actions = {tuple(c["change"]["actions"]) for c in plan["resource_changes"] if c["mode"] == "managed"}
    assert actions == {("create",)}
    assert not [a for a in resources if a.startswith("aws_organizations_policy_attachment")]


def test_policy_types(resources):
    assert values(resources, "aws_organizations_policy.guardrails")["type"] == "SERVICE_CONTROL_POLICY"
    assert values(resources, "aws_organizations_policy.data_perimeter")["type"] == "RESOURCE_CONTROL_POLICY"


def test_trail_is_org_wide_validated_and_encrypted(resources):
    trail = values(resources, "aws_cloudtrail.org")
    assert trail["is_organization_trail"] is True
    assert trail["is_multi_region_trail"] is True
    assert trail["enable_log_file_validation"] is True
    assert trail["include_global_service_events"] is True


def test_trail_and_bucket_reference_the_cmk():
    # The key ARN is only known after apply, so check the configuration references instead.
    config = json.loads(PLAN.read_text())["configuration"]["root_module"]["resources"]
    by_addr = {r["address"]: r for r in config}
    trail_refs = by_addr["aws_cloudtrail.org"]["expressions"]["kms_key_id"]["references"]
    assert "aws_kms_key.cloudtrail.arn" in trail_refs
    sse = by_addr["aws_s3_bucket_server_side_encryption_configuration.trail"]["expressions"]["rule"][0]
    refs = sse["apply_server_side_encryption_by_default"][0]["kms_master_key_id"]["references"]
    assert "aws_kms_key.cloudtrail.arn" in refs


def test_key_rotation_and_deletion_window(resources):
    key = values(resources, "aws_kms_key.cloudtrail")
    assert key["enable_key_rotation"] is True
    assert key["deletion_window_in_days"] == 30


@pytest.mark.parametrize(
    "address", ["aws_s3_account_public_access_block.this", "aws_s3_bucket_public_access_block.trail"]
)
def test_block_public_access_is_fully_on(resources, address):
    v = values(resources, address)
    for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
        assert v[key] is True, key


def test_trail_bucket_controls(resources):
    assert (
        values(resources, "aws_s3_bucket_ownership_controls.trail")["rule"][0]["object_ownership"]
        == "BucketOwnerEnforced"
    )
    assert (
        values(resources, "aws_s3_bucket_versioning.trail")["versioning_configuration"][0]["status"]
        == "Enabled"
    )
    sse = values(resources, "aws_s3_bucket_server_side_encryption_configuration.trail")["rule"][0]
    assert sse["apply_server_side_encryption_by_default"][0]["sse_algorithm"] == "aws:kms"


def test_remediation_function_settings(resources):
    fn = values(resources, "aws_lambda_function.remediation")
    assert fn["reserved_concurrent_executions"] == 5
    assert fn["tracing_config"][0]["mode"] == "Active"
    assert fn["environment"][0]["variables"] == {"DRY_RUN": "false", "EXEMPT_BUCKETS": ""}
    assert fn["runtime"] == "python3.12"


def test_eventbridge_rules_use_repo_patterns(resources):
    for key in ("s3-bpa-api-change", "guardduty-s3-bpa-disabled"):
        rule = values(resources, f'aws_cloudwatch_event_rule.remediation["{key}"]')
        expected = json.loads((REPO / "terraform" / "event-patterns" / f"{key}.json").read_text())
        assert json.loads(rule["event_pattern"]) == expected


def test_detection_services_planned(resources):
    assert values(resources, "aws_guardduty_detector.this")["enable"] is True
    assert values(resources, "aws_guardduty_detector_feature.s3_data_events[0]")["status"] == "ENABLED"
    assert values(resources, "aws_securityhub_account.this[0]")["enable_default_standards"] is False
    org = values(resources, "aws_guardduty_organization_configuration.this")
    assert org["auto_enable_organization_members"] == "ALL"


def test_trail_bucket_logging_notifications_and_replication(resources):
    logging = values(resources, "aws_s3_bucket_logging.trail")
    assert logging["target_prefix"] == "org-trail/"
    notification = values(resources, "aws_s3_bucket_notification.trail")
    assert notification["eventbridge"] is True
    repl = values(resources, "aws_s3_bucket_replication_configuration.trail")
    rule = repl["rule"][0]
    assert rule["status"] == "Enabled"
    assert rule["source_selection_criteria"][0]["sse_kms_encrypted_objects"][0]["status"] == "Enabled"


def test_remediation_log_group_uses_cmk(resources):
    group = values(resources, "aws_cloudwatch_log_group.remediation")
    assert group["retention_in_days"] == 365
    config = json.loads(PLAN.read_text())["configuration"]["root_module"]["resources"]
    by_addr = {r["address"]: r for r in config}
    refs = by_addr["aws_cloudwatch_log_group.remediation"]["expressions"]["kms_key_id"]["references"]
    assert "aws_kms_key.lab_logs.arn" in refs


def test_access_log_destinations_follow_aws_guidance(resources):
    """Log destinations use SSE-S3 and no bucket logs to itself."""
    for address in (
        "aws_s3_bucket_server_side_encryption_configuration.access_logs",
        "aws_s3_bucket_server_side_encryption_configuration.replica_access_logs",
    ):
        sse = values(resources, address)["rule"][0]["apply_server_side_encryption_by_default"][0]
        assert sse["sse_algorithm"] == "AES256", address
        assert not sse.get("kms_master_key_id")

    # Bucket names are known only after apply, so check the configuration references.
    config = json.loads(PLAN.read_text())["configuration"]["root_module"]["resources"]
    by_addr = {r["address"]: r for r in config}

    trail = by_addr["aws_s3_bucket_logging.trail"]["expressions"]
    assert "aws_s3_bucket.trail.id" in trail["bucket"]["references"]
    assert "aws_s3_bucket.access_logs.id" in trail["target_bucket"]["references"]
    assert values(resources, "aws_s3_bucket_logging.trail")["target_prefix"] == "org-trail/"

    replica = by_addr["aws_s3_bucket_logging.trail_replica"]["expressions"]
    assert "aws_s3_bucket.trail_replica.id" in replica["bucket"]["references"]
    assert "aws_s3_bucket.replica_access_logs.id" in replica["target_bucket"]["references"]
    assert values(resources, "aws_s3_bucket_logging.trail_replica")["target_prefix"] == "org-trail-replica/"

    assert "aws_s3_bucket_logging.access_logs" not in by_addr
    assert "aws_s3_bucket_logging.replica_access_logs" not in by_addr
