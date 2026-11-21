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


def test_workload_vpc_is_isolated_and_has_flow_logs(resources):
    vpc = values(resources, "aws_vpc.workload")
    assert vpc["cidr_block"] == "10.42.0.0/16"
    assert vpc["enable_dns_support"] is True
    assert vpc["enable_dns_hostnames"] is True

    flow = values(resources, "aws_flow_log.workload")
    assert flow["traffic_type"] == "ALL"
    assert flow["log_destination_type"] == "cloud-watch-logs"
    assert flow["max_aggregation_interval"] == 60

    default_sg = values(resources, "aws_default_security_group.workload")
    assert default_sg.get("ingress") in (None, [], [{}]) or default_sg["ingress"] == []
    # Default SG should have no ingress or egress rules.
    for key in ("ingress", "egress"):
        rules = default_sg.get(key) or []
        assert rules == [] or rules == [{}], (key, rules)


def test_app_security_group_has_no_ssh_and_no_open_ingress(resources):
    # Ingress and egress live on the dedicated rule resources in plan JSON.
    ingress_addrs = [a for a in resources if a.startswith("aws_vpc_security_group_ingress_rule.")]
    egress_addrs = [a for a in resources if a.startswith("aws_vpc_security_group_egress_rule.")]
    for address in ingress_addrs:
        rule = values(resources, address)
        assert not (rule.get("from_port") == 22 or rule.get("to_port") == 22), address
        assert rule.get("cidr_ipv4") != "0.0.0.0/0", address
    # App ingress is empty: only the endpoints SG has an ingress rule.
    assert ingress_addrs == ["aws_vpc_security_group_ingress_rule.endpoints_https_from_app"]
    assert "aws_vpc_security_group_egress_rule.app_https_to_endpoints" in egress_addrs


def test_app_network_acl_denies_ssh(resources):
    deny_in = values(resources, "aws_network_acl_rule.app_ingress_deny_ssh")
    deny_out = values(resources, "aws_network_acl_rule.app_egress_deny_ssh")
    for rule in (deny_in, deny_out):
        assert rule["rule_action"] == "deny"
        assert rule["from_port"] == 22
        assert rule["to_port"] == 22
        assert rule["cidr_block"] == "0.0.0.0/0"


def test_vpc_endpoints_include_session_manager_and_s3(resources):
    s3 = values(resources, "aws_vpc_endpoint.s3")
    assert s3["vpc_endpoint_type"] == "Gateway"
    assert s3["service_name"].endswith(".s3")
    for service in ("ssm", "ssmmessages", "ec2messages"):
        ep = values(resources, f'aws_vpc_endpoint.interface["{service}"]')
        assert ep["vpc_endpoint_type"] == "Interface"
        assert ep["private_dns_enabled"] is True
        assert ep["service_name"].endswith(f".{service}")
    logs = values(resources, "aws_vpc_endpoint.logs")
    assert logs["vpc_endpoint_type"] == "Interface"
    assert logs["private_dns_enabled"] is True
    assert logs["service_name"].endswith(".logs")


def test_app_and_endpoint_security_groups_have_no_allow_all_egress_rule(resources):
    """Explicit egress is HTTPS only. The provider revokes AWS's default allow-all
    egress on create; that revoke is not visible in an offline plan."""
    for address, rule in resources.items():
        if not address.startswith("aws_vpc_security_group_egress_rule."):
            continue
        v = rule["values"]
        protocol = str(v.get("ip_protocol"))
        cidr = v.get("cidr_ipv4")
        assert not (protocol in {"-1", "-1.0"} and cidr == "0.0.0.0/0"), address
        if v.get("from_port") is not None:
            assert v["from_port"] == 443, address
            assert v["to_port"] == 443, address


def test_launch_template_requires_imdsv2_encrypts_ebs_and_has_no_ssh_key(resources):
    lt = values(resources, "aws_launch_template.workload")
    meta = lt["metadata_options"][0]
    assert meta["http_endpoint"] == "enabled"
    assert meta["http_tokens"] == "required"
    assert meta["http_put_response_hop_limit"] == 1
    ebs = lt["block_device_mappings"][0]["ebs"][0]
    assert ebs["encrypted"] == "true" or ebs["encrypted"] is True
    assert ebs["volume_type"] == "gp3"
    nic = lt["network_interfaces"][0]
    assert nic["associate_public_ip_address"] == "false" or nic["associate_public_ip_address"] is False
    assert not lt.get("key_name")
    assert "aws_instance.workload" not in resources


def test_waf_has_managed_common_rules_and_rate_limit(resources):
    acl = values(resources, "aws_wafv2_web_acl.edge")
    assert acl["scope"] == "REGIONAL"
    rules = {r["name"]: r for r in acl["rule"]}
    assert "AWSManagedRulesKnownBadInputsRuleSet" in rules
    assert "AWSManagedRulesCommonRuleSet" in rules
    assert "RateLimitByIP" in rules
    bad_inputs = rules["AWSManagedRulesKnownBadInputsRuleSet"]["statement"][0][
        "managed_rule_group_statement"
    ][0]
    assert bad_inputs["name"] == "AWSManagedRulesKnownBadInputsRuleSet"
    assert bad_inputs["vendor_name"] == "AWS"
    rate = rules["RateLimitByIP"]["statement"][0]["rate_based_statement"][0]
    assert rate["limit"] == 1000
    assert rate["aggregate_key_type"] == "IP"
    managed = rules["AWSManagedRulesCommonRuleSet"]["statement"][0]["managed_rule_group_statement"][0]
    assert managed["name"] == "AWSManagedRulesCommonRuleSet"
    assert managed["vendor_name"] == "AWS"


def test_inspector_enables_ec2_ecr_and_lambda(resources):
    enabler = values(resources, "aws_inspector2_enabler.this[0]")
    assert set(enabler["account_ids"]) == {"111122223333"}
    assert set(enabler["resource_types"]) == {"EC2", "ECR", "LAMBDA"}


def test_domain3_policies_match_templates(resources):
    from scs_lab.render import render_policy

    s3_policy = values(resources, "aws_vpc_endpoint.s3")["policy"]
    assert json.loads(s3_policy) == render_policy("vpce-s3")
    ssm_policy = values(resources, 'aws_vpc_endpoint.interface["ssm"]')["policy"]
    assert json.loads(ssm_policy) == render_policy("vpce-ssm")
    logs_policy = values(resources, "aws_vpc_endpoint.logs")["policy"]
    assert json.loads(logs_policy) == render_policy("vpce-logs")
    instance = values(resources, "aws_iam_policy.ssm_instance")["policy"]
    assert json.loads(instance) == render_policy("iam-ssm-instance")
    operator = values(resources, "aws_iam_policy.ssm_operator")["policy"]
    assert json.loads(operator) == render_policy("iam-ssm-operator")
