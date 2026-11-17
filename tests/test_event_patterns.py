"""Route sample events through moto's EventBridge matcher into an SQS target.

moto's matcher is an approximation of EventBridge pattern matching, and real
EventBridge rejects PutEvents calls that use an aws.* source. These tests
check that the patterns select the events the Lambda handles, not that AWS
would deliver them.
"""

import json

import boto3
import pytest
from moto import mock_aws

from conftest import REPO, load_event

PATTERNS = REPO / "terraform" / "event-patterns"


def with_id(event: dict, new_id: str, **detail_updates) -> dict:
    event = json.loads(json.dumps(event))
    event["detail"].update(detail_updates)
    event["detail"]["_sample"] = new_id
    return event


def routed_samples(pattern_file: str, events: list[dict]) -> list[str]:
    with mock_aws():
        events_client = boto3.client("events", region_name="us-east-1")
        sqs = boto3.client("sqs", region_name="us-east-1")
        url = sqs.create_queue(QueueName="capture")["QueueUrl"]
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        events_client.put_rule(Name="rule", EventPattern=(PATTERNS / pattern_file).read_text())
        events_client.put_targets(Rule="rule", Targets=[{"Id": "capture", "Arn": arn}])
        for event in events:
            events_client.put_events(
                Entries=[
                    {
                        "Source": event["source"],
                        "DetailType": event["detail-type"],
                        "Detail": json.dumps(event["detail"]),
                    }
                ]
            )
        messages = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10).get("Messages", [])
        return sorted(json.loads(m["Body"])["detail"]["_sample"] for m in messages)


def test_cloudtrail_pattern_selects_bpa_changes_only():
    base = load_event("cloudtrail-delete-bpa")
    samples = [
        with_id(base, "delete"),
        with_id(base, "put", eventName="PutBucketPublicAccessBlock"),
        with_id(base, "policy", eventName="PutBucketPolicy"),
        with_id(base, "account-level", eventName="PutAccountPublicAccessBlock"),
    ]
    assert routed_samples("s3-bpa-api-change.json", samples) == ["delete", "put"]


def test_guardduty_pattern_selects_bpa_disabled_finding_only():
    base = load_event("guardduty-bpa-disabled")
    samples = [
        with_id(base, "bpa-disabled"),
        with_id(base, "public-granted", type="Policy:S3/BucketPublicAccessGranted"),
        with_id(base, "account-bpa", type="Policy:S3/AccountBlockPublicAccessDisabled"),
    ]
    assert routed_samples("guardduty-s3-bpa-disabled.json", samples) == ["bpa-disabled"]


@pytest.mark.parametrize("pattern", ["s3-bpa-api-change.json", "guardduty-s3-bpa-disabled.json"])
def test_patterns_are_valid_json_with_source_filter(pattern):
    data = json.loads((PATTERNS / pattern).read_text())
    assert data["source"] and data["detail-type"] and data["detail"]
