import json
import re

import pytest

from conftest import REPO
from scs_lab.policy_eval import Request, Unsupported, evaluate
from scs_lab.render import (
    EXAMPLE_BOUNDARY_ARN,
    EXAMPLE_BUCKET,
    EXAMPLE_LOG_READER,
    EXAMPLE_TRAIL_ARN,
    POLICY_DIR,
    TEMPLATE_VARS,
    TemplateError,
    render_policy,
    render_text,
)

DEV_ROLE = "arn:aws:iam::777788889999:role/Developer"
BREAK_GLASS = "arn:aws:iam::777788889999:role/BreakGlassAdmin"
PLACEHOLDER_ACCOUNTS = {"111122223333", "444455556666", "777788889999"}


def decide(policy_name, action, resource="*", **kwargs):
    context = kwargs.pop("context", {})
    return evaluate(
        render_policy(policy_name), Request(action=action, resource=resource, context=context, **kwargs)
    )


# --- rendering and size limits -------------------------------------------------


@pytest.mark.parametrize("name", sorted(TEMPLATE_VARS))
def test_every_template_renders_to_policy_json(name):
    policy = render_policy(name)
    assert policy["Version"] == "2012-10-17"
    assert policy["Statement"]
    sids = [s.get("Sid") for s in policy["Statement"]]
    assert all(sids) and len(sids) == len(set(sids)), "every statement needs a unique Sid"


def test_every_template_file_has_vars():
    files = {p.name.removesuffix(".json.tftpl") for p in POLICY_DIR.glob("*.json.tftpl")}
    assert files == set(TEMPLATE_VARS)


def test_renderer_rejects_unknown_expressions():
    with pytest.raises(TemplateError):
        render_text("${upper(x)}", {"x": "a"})
    with pytest.raises(TemplateError):
        render_text("${missing}", {})
    with pytest.raises(TemplateError):
        render_text("${items}", {"items": ["a"]})


def test_scp_and_rcp_fit_organizations_size_limits():
    # Terraform sends the rendered text as-is, whitespace included, and the
    # Organizations quotas page says SDK/CLI submissions are counted exactly.
    scp = render_text((POLICY_DIR / "scp-guardrails.json.tftpl").read_text(), TEMPLATE_VARS["scp-guardrails"])
    rcp = render_text(
        (POLICY_DIR / "rcp-data-perimeter.json.tftpl").read_text(), TEMPLATE_VARS["rcp-data-perimeter"]
    )
    assert len(scp) <= 10240, len(scp)
    assert len(rcp) <= 5120, len(rcp)


def test_repo_uses_only_placeholder_account_ids():
    skip_dirs = {".venv", ".git", "build", ".terraform", "__pycache__", ".pytest_cache", ".ruff_cache"}
    found = set()
    for path in REPO.rglob("*"):
        if path.is_dir() or any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix not in {
            ".tf",
            ".tftpl",
            ".json",
            ".py",
            ".md",
            ".sh",
            ".toml",
            ".hcl",
            ".yml",
            ".yaml",
        }:
            continue
        found |= set(re.findall(r"(?<![0-9-])[0-9]{12}(?![0-9])", path.read_text(encoding="utf-8")))
    assert found <= PLACEHOLDER_ACCOUNTS, found - PLACEHOLDER_ACCOUNTS


# --- SCP guardrails -----------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "guardduty:DeleteDetector",
        "securityhub:DisableSecurityHub",
    ],
)
def test_scp_denies_telemetry_tampering_for_normal_roles(action):
    d = decide(
        "scp-guardrails", action, context={"aws:PrincipalArn": DEV_ROLE, "aws:RequestedRegion": "us-east-1"}
    )
    assert d.decision == "explicit_deny"
    assert "ProtectSecurityTelemetry" in d.matched_deny


def test_scp_exempts_break_glass_from_telemetry_protection():
    d = decide(
        "scp-guardrails",
        "cloudtrail:StopLogging",
        context={"aws:PrincipalArn": BREAK_GLASS, "aws:RequestedRegion": "us-east-1"},
    )
    assert d.decision == "no_match"


def test_scp_leave_organization_is_denied_even_for_break_glass():
    d = decide("scp-guardrails", "organizations:LeaveOrganization", context={"aws:PrincipalArn": BREAK_GLASS})
    assert d.matched_deny == ["DenyLeaveOrganization"]


def test_scp_denies_root_user():
    d = decide(
        "scp-guardrails",
        "s3:GetObject",
        context={"aws:PrincipalArn": "arn:aws:iam::777788889999:root", "aws:RequestedRegion": "us-east-1"},
    )
    assert "DenyRootUserActions" in d.matched_deny


@pytest.mark.parametrize(
    ("action", "region", "expected"),
    [
        ("ec2:RunInstances", "eu-west-1", "explicit_deny"),
        ("ec2:RunInstances", "us-west-2", "no_match"),
        ("iam:CreateRole", "eu-west-1", "no_match"),  # global service in NotAction
        ("s3:PutAccountPublicAccessBlock", "eu-west-1", "explicit_deny"),  # separate statement
    ],
)
def test_scp_region_guardrail(action, region, expected):
    d = decide(
        "scp-guardrails", action, context={"aws:PrincipalArn": DEV_ROLE, "aws:RequestedRegion": region}
    )
    assert d.decision == expected


def test_scp_region_guardrail_exempts_break_glass():
    d = decide(
        "scp-guardrails",
        "ec2:RunInstances",
        context={"aws:PrincipalArn": BREAK_GLASS, "aws:RequestedRegion": "eu-west-1"},
    )
    assert d.decision == "no_match"


def test_scp_never_allows():
    policy = render_policy("scp-guardrails")
    assert {s["Effect"] for s in policy["Statement"]} == {"Deny"}


# --- RCP data perimeter -------------------------------------------------------------


def test_rcp_denies_plain_http():
    d = decide(
        "rcp-data-perimeter",
        "s3:GetObject",
        "arn:aws:s3:::scs-lab-app-data/a.txt",
        principal_arn=DEV_ROLE,
        context={"aws:SecureTransport": "false", "aws:PrincipalOrgID": "o-exampleorg1"},
    )
    assert d.matched_deny == ["EnforceSecureTransport"]


def test_rcp_denies_identities_outside_org():
    d = decide(
        "rcp-data-perimeter",
        "s3:GetObject",
        "arn:aws:s3:::scs-lab-app-data/a.txt",
        principal_arn="arn:aws:iam::777788889999:role/Outsider",
        context={
            "aws:SecureTransport": "true",
            "aws:PrincipalOrgID": "o-otherorg000",
            "aws:PrincipalIsAWSService": "false",
        },
    )
    assert d.matched_deny == ["EnforceOrgIdentitiesOnS3"]


def test_rcp_denies_anonymous_requests():
    d = decide(
        "rcp-data-perimeter",
        "s3:GetObject",
        "arn:aws:s3:::scs-lab-app-data/a.txt",
        context={"aws:SecureTransport": "true"},
    )
    assert d.matched_deny == ["EnforceOrgIdentitiesOnS3"]


def test_rcp_lets_aws_service_principals_through():
    d = decide(
        "rcp-data-perimeter",
        "s3:PutObject",
        "arn:aws:s3:::scs-lab-app-data/AWSLogs/x",
        principal_service="cloudtrail.amazonaws.com",
        context={"aws:SecureTransport": "true", "aws:PrincipalIsAWSService": "true"},
    )
    assert d.decision == "no_match"


def test_rcp_lets_org_identities_over_tls_through():
    d = decide(
        "rcp-data-perimeter",
        "s3:GetObject",
        "arn:aws:s3:::scs-lab-app-data/a.txt",
        principal_arn=DEV_ROLE,
        context={
            "aws:SecureTransport": "true",
            "aws:PrincipalOrgID": "o-exampleorg1",
            "aws:PrincipalIsAWSService": "false",
        },
    )
    assert d.decision == "no_match"


# --- KMS key policy -----------------------------------------------------------------

USE_ACTIONS = {"kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:*"}


def test_kms_admins_cannot_use_the_key():
    policy = render_policy("kms-cloudtrail-key-policy")
    admin = next(s for s in policy["Statement"] if s["Sid"] == "KeyAdministrationWithoutUse")
    assert not USE_ACTIONS & set(admin["Action"])
    for action in ("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"):
        d = decide(
            "kms-cloudtrail-key-policy", action, principal_arn="arn:aws:iam::111122223333:role/KeyAdmin"
        )
        assert d.decision == "no_match", action


def test_kms_no_wildcard_principal_and_no_kms_star():
    policy = render_policy("kms-cloudtrail-key-policy")
    for stmt in policy["Statement"]:
        assert stmt["Principal"] != "*"
        assert "kms:*" not in (stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]])


def test_kms_cloudtrail_encrypt_requires_trail_source_arn():
    ok = decide(
        "kms-cloudtrail-key-policy",
        "kms:GenerateDataKey",
        principal_service="cloudtrail.amazonaws.com",
        context={
            "aws:SourceArn": EXAMPLE_TRAIL_ARN,
            "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:us-east-1:111122223333:trail/scs-lab-org-trail",
        },
    )
    assert ok.decision == "allow"
    other_trail = decide(
        "kms-cloudtrail-key-policy",
        "kms:GenerateDataKey",
        principal_service="cloudtrail.amazonaws.com",
        context={
            "aws:SourceArn": "arn:aws:cloudtrail:us-east-1:111122223333:trail/someone-elses-trail",
            "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:us-east-1:111122223333:trail/x",
        },
    )
    assert other_trail.decision == "no_match"


def test_kms_log_reader_decrypt_needs_s3_and_cloudtrail_context():
    good = {
        "kms:ViaService": "s3.us-east-1.amazonaws.com",
        "kms:EncryptionContext:aws:cloudtrail:arn": EXAMPLE_TRAIL_ARN,
    }
    assert (
        decide(
            "kms-cloudtrail-key-policy", "kms:Decrypt", principal_arn=EXAMPLE_LOG_READER, context=good
        ).decision
        == "allow"
    )
    direct = {"kms:EncryptionContext:aws:cloudtrail:arn": EXAMPLE_TRAIL_ARN}
    assert (
        decide(
            "kms-cloudtrail-key-policy", "kms:Decrypt", principal_arn=EXAMPLE_LOG_READER, context=direct
        ).decision
        == "no_match"
    )
    no_ctx = {"kms:ViaService": "s3.us-east-1.amazonaws.com"}
    assert (
        decide(
            "kms-cloudtrail-key-policy", "kms:Decrypt", principal_arn=EXAMPLE_LOG_READER, context=no_ctx
        ).decision
        == "no_match"
    )


# --- Trail bucket policy ----------------------------------------------------------------


def test_bucket_allows_cloudtrail_org_write_with_acl_and_source_arn():
    d = decide(
        "s3-trail-bucket-policy",
        "s3:PutObject",
        f"arn:aws:s3:::{EXAMPLE_BUCKET}/AWSLogs/o-exampleorg1/777788889999/CloudTrail/x.json.gz",
        principal_service="cloudtrail.amazonaws.com",
        context={
            "s3:x-amz-acl": "bucket-owner-full-control",
            "aws:SourceArn": EXAMPLE_TRAIL_ARN,
            "aws:SecureTransport": "true",
        },
    )
    assert d.decision == "allow"
    assert d.matched_allow == ["AWSCloudTrailOrganizationWrite"]


def test_bucket_rejects_write_from_other_trail():
    d = decide(
        "s3-trail-bucket-policy",
        "s3:PutObject",
        f"arn:aws:s3:::{EXAMPLE_BUCKET}/AWSLogs/o-exampleorg1/x",
        principal_service="cloudtrail.amazonaws.com",
        context={
            "s3:x-amz-acl": "bucket-owner-full-control",
            "aws:SourceArn": "arn:aws:cloudtrail:us-east-1:777788889999:trail/rogue",
            "aws:SecureTransport": "true",
        },
    )
    assert d.decision == "no_match"


def test_bucket_denies_log_deletion_and_plain_http():
    d = decide(
        "s3-trail-bucket-policy",
        "s3:DeleteObject",
        f"arn:aws:s3:::{EXAMPLE_BUCKET}/AWSLogs/x",
        principal_arn="arn:aws:iam::111122223333:role/TerraformDeployer",
        context={"aws:SecureTransport": "true"},
    )
    assert d.matched_deny == ["DenyLogDeletion"]
    d = decide(
        "s3-trail-bucket-policy",
        "s3:GetObject",
        f"arn:aws:s3:::{EXAMPLE_BUCKET}/AWSLogs/x",
        principal_arn=EXAMPLE_LOG_READER,
        context={"aws:SecureTransport": "false"},
    )
    assert d.decision == "explicit_deny"


def test_log_reader_can_read_but_not_write():
    read = decide(
        "s3-trail-bucket-policy",
        "s3:GetObject",
        f"arn:aws:s3:::{EXAMPLE_BUCKET}/AWSLogs/x",
        principal_arn=EXAMPLE_LOG_READER,
        context={"aws:SecureTransport": "true"},
    )
    write = decide(
        "s3-trail-bucket-policy",
        "s3:PutObject",
        f"arn:aws:s3:::{EXAMPLE_BUCKET}/AWSLogs/x",
        principal_arn=EXAMPLE_LOG_READER,
        context={"aws:SecureTransport": "true"},
    )
    assert read.decision == "allow"
    assert write.decision == "no_match"


# --- Permission boundary delegation ----------------------------------------------------

APP_ROLE = "arn:aws:iam::111122223333:role/app/orders-fn"


def test_role_creator_can_create_role_only_with_boundary():
    with_boundary = decide(
        "iam-role-creator",
        "iam:CreateRole",
        APP_ROLE,
        context={"iam:PermissionsBoundary": EXAMPLE_BOUNDARY_ARN},
    )
    without = decide("iam-role-creator", "iam:CreateRole", APP_ROLE)
    other = decide(
        "iam-role-creator",
        "iam:CreateRole",
        APP_ROLE,
        context={"iam:PermissionsBoundary": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    assert with_boundary.decision == "allow"
    assert without.decision == "no_match"
    assert other.decision == "no_match"


def test_role_creator_cannot_create_roles_outside_app_path():
    d = decide(
        "iam-role-creator",
        "iam:CreateRole",
        "arn:aws:iam::111122223333:role/admin",
        context={"iam:PermissionsBoundary": EXAMPLE_BOUNDARY_ARN},
    )
    assert d.decision == "no_match"


def test_role_creator_cannot_remove_or_edit_boundary():
    assert (
        decide("iam-role-creator", "iam:DeleteRolePermissionsBoundary", APP_ROLE).decision == "explicit_deny"
    )
    assert (
        decide("iam-role-creator", "iam:CreatePolicyVersion", EXAMPLE_BOUNDARY_ARN).decision
        == "explicit_deny"
    )


def test_role_creator_passrole_only_to_lambda():
    assert (
        decide(
            "iam-role-creator",
            "iam:PassRole",
            APP_ROLE,
            context={"iam:PassedToService": "lambda.amazonaws.com"},
        ).decision
        == "allow"
    )
    assert (
        decide(
            "iam-role-creator", "iam:PassRole", APP_ROLE, context={"iam:PassedToService": "ec2.amazonaws.com"}
        ).decision
        == "no_match"
    )


def test_boundary_caps_workload_and_blocks_iam():
    assert (
        decide("iam-workload-boundary", "s3:GetObject", "arn:aws:s3:::scs-lab-app-orders/x").decision
        == "allow"
    )
    assert (
        decide("iam-workload-boundary", "s3:GetObject", f"arn:aws:s3:::{EXAMPLE_BUCKET}/x").decision
        == "no_match"
    )
    assert decide("iam-workload-boundary", "iam:CreateUser", "*").decision == "explicit_deny"


# --- Remediation Lambda role -----------------------------------------------------------


def test_lambda_role_scoped_to_own_account():
    own = decide(
        "lambda-remediation-role",
        "s3:PutBucketPublicAccessBlock",
        "arn:aws:s3:::any-bucket",
        context={"aws:ResourceAccount": "111122223333"},
    )
    other = decide(
        "lambda-remediation-role",
        "s3:PutBucketPublicAccessBlock",
        "arn:aws:s3:::any-bucket",
        context={"aws:ResourceAccount": "777788889999"},
    )
    assert own.decision == "allow"
    assert other.decision == "no_match"
    assert (
        decide("lambda-remediation-role", "s3:PutBucketPolicy", "arn:aws:s3:::any-bucket").decision
        == "no_match"
    )


# --- Evaluator semantics -----------------------------------------------------------------


def _one(condition):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "S", "Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": condition}
        ],
    }


@pytest.mark.parametrize(
    ("condition", "context", "expected"),
    [
        ({"StringEquals": {"k": "v"}}, {}, "no_match"),  # missing key, positive operator
        ({"StringNotEquals": {"k": "v"}}, {}, "allow"),  # missing key, negated operator
        ({"StringEqualsIfExists": {"k": "v"}}, {}, "allow"),
        ({"StringEqualsIfExists": {"k": "v"}}, {"k": "x"}, "no_match"),
        ({"Null": {"k": "true"}}, {}, "allow"),
        ({"Null": {"k": "false"}}, {}, "no_match"),
        ({"Bool": {"k": "false"}}, {"k": False}, "allow"),
        ({"ArnLike": {"k": "arn:aws:iam::*:role/x"}}, {"k": "arn:aws:iam::111122223333:role/x"}, "allow"),
        ({"ArnLike": {"k": "arn:aws:iam::*:role/x"}}, {"k": "arn:aws:iam::111122223333:user/x"}, "no_match"),
    ],
)
def test_evaluator_condition_semantics(condition, context, expected):
    assert evaluate(_one(condition), Request("s3:GetObject", context=context)).decision == expected


@pytest.mark.parametrize(
    "condition",
    [
        {"ForAnyValue:StringEquals": {"k": "v"}},
        {"NumericLessThan": {"k": "1"}},
        {"NullIfExists": {"k": "true"}},
    ],
)
def test_evaluator_refuses_unsupported_grammar(condition):
    with pytest.raises(Unsupported):
        evaluate(_one(condition), Request("s3:GetObject", context={"k": "v"}))


def test_evaluator_refuses_not_principal_and_multivalued_keys():
    policy = {"Statement": [{"Effect": "Deny", "NotPrincipal": {"AWS": "x"}, "Action": "*", "Resource": "*"}]}
    with pytest.raises(Unsupported):
        evaluate(policy, Request("s3:GetObject"))
    with pytest.raises(Unsupported):
        evaluate(_one({"StringEquals": {"k": "v"}}), Request("s3:GetObject", context={"k": ["v"]}))


def test_action_matching_is_case_insensitive():
    policy = {"Statement": [{"Sid": "S", "Effect": "Deny", "Action": "CloudTrail:Stop*", "Resource": "*"}]}
    assert evaluate(policy, Request("cloudtrail:StopLogging")).decision == "explicit_deny"


def test_rendered_output_round_trips_as_json():
    for name in TEMPLATE_VARS:
        assert json.loads(json.dumps(render_policy(name))) == render_policy(name)
