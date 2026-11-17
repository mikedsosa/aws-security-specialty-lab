import copy

import boto3
import pytest
from moto import mock_aws

import handler
from conftest import load_event

BUCKET = "scs-lab-app-data"


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def bpa(client, bucket=BUCKET):
    return handler.current_block(client, bucket)


def weaken(client, bucket=BUCKET):
    client.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )


def test_delete_event_restores_missing_configuration(s3, monkeypatch):
    monkeypatch.delenv("EXEMPT_BUCKETS", raising=False)
    s3.delete_public_access_block(Bucket=BUCKET)
    result = handler.lambda_handler(load_event("cloudtrail-delete-bpa"), s3=s3)
    assert result["results"] == [
        {"bucket": BUCKET, "action": "restored", "before": {k: False for k in handler.FULL_BLOCK}}
    ]
    assert bpa(s3) == handler.FULL_BLOCK


def test_partial_put_event_restores_full_block(s3):
    weaken(s3)
    result = handler.lambda_handler(load_event("cloudtrail-put-bpa-partial"), s3=s3)
    assert result["results"][0]["action"] == "restored"
    assert bpa(s3) == handler.FULL_BLOCK


def test_own_remediation_event_is_a_no_op(s3):
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=dict(handler.FULL_BLOCK))
    event = load_event("cloudtrail-put-bpa-partial")
    event["detail"]["requestParameters"]["PublicAccessBlockConfiguration"] = dict(handler.FULL_BLOCK)
    result = handler.lambda_handler(event, s3=s3)
    assert result["results"] == [{"bucket": BUCKET, "action": "already_compliant"}]


def test_guardduty_finding_restores(s3):
    weaken(s3)
    result = handler.lambda_handler(load_event("guardduty-bpa-disabled"), s3=s3)
    assert result["handled"] is True
    assert result["results"][0]["action"] == "restored"
    assert bpa(s3) == handler.FULL_BLOCK


def test_exempt_bucket_is_left_alone(s3, monkeypatch):
    monkeypatch.setenv("EXEMPT_BUCKETS", f"other-bucket, {BUCKET}")
    weaken(s3)
    result = handler.lambda_handler(load_event("cloudtrail-put-bpa-partial"), s3=s3)
    assert result["results"] == [{"bucket": BUCKET, "action": "skipped_exempt"}]
    assert bpa(s3)["BlockPublicPolicy"] is False


def test_dry_run_changes_nothing(s3, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    weaken(s3)
    result = handler.lambda_handler(load_event("cloudtrail-put-bpa-partial"), s3=s3)
    assert result["dry_run"] is True
    assert result["results"][0]["action"] == "would_restore"
    assert bpa(s3)["BlockPublicPolicy"] is False


def test_failed_api_call_is_ignored(s3):
    event = load_event("cloudtrail-delete-bpa")
    event["detail"]["errorCode"] = "AccessDenied"
    assert handler.lambda_handler(event, s3=s3) == {"handled": False, "results": []}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update({"source": "aws.ec2"}),
        lambda e: e["detail"].update({"eventName": "PutBucketPolicy"}),
        lambda e: e.update({"detail": None}),
        lambda e: e["detail"].update({"requestParameters": None}),
        lambda e: e["detail"].update({"requestParameters": {"bucketName": ""}}),
    ],
)
def test_unrelated_or_malformed_cloudtrail_events_are_ignored(s3, mutate):
    event = copy.deepcopy(load_event("cloudtrail-delete-bpa"))
    mutate(event)
    assert handler.lambda_handler(event, s3=s3)["handled"] is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e["detail"].update({"type": "Policy:S3/BucketPublicAccessGranted"}),
        lambda e: e["detail"].update({"resource": None}),
        lambda e: e["detail"]["resource"].update({"s3BucketDetails": [{"name": 7}]}),
    ],
)
def test_unrelated_or_malformed_guardduty_events_are_ignored(s3, mutate):
    event = copy.deepcopy(load_event("guardduty-bpa-disabled"))
    mutate(event)
    assert handler.lambda_handler(event, s3=s3)["handled"] is False


def test_non_dict_event_is_ignored():
    assert handler.bucket_names_from_event("not an event") == []


def test_missing_bucket_raises_so_eventbridge_retries(s3):
    event = load_event("cloudtrail-delete-bpa")
    event["detail"]["requestParameters"]["bucketName"] = "does-not-exist"
    with pytest.raises(Exception):  # noqa: B017 - any client error should surface
        handler.lambda_handler(event, s3=s3)
