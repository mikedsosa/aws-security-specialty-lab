"""Turn S3 bucket-level Block Public Access back on after it is weakened.

Triggered by EventBridge for two event shapes:

* CloudTrail management events (``detail-type`` "AWS API Call via CloudTrail")
  for ``DeleteBucketPublicAccessBlock`` and ``PutBucketPublicAccessBlock``.
* GuardDuty findings of type ``Policy:S3/BucketBlockPublicAccessDisabled``.

The function reads the bucket's current configuration before acting, so an
event caused by its own ``PutBucketPublicAccessBlock`` call is a no-op.
Buckets named in ``EXEMPT_BUCKETS`` are skipped. ``DRY_RUN=true`` logs the
decision without changing anything.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

CLOUDTRAIL_EVENT_NAMES = {"DeleteBucketPublicAccessBlock", "PutBucketPublicAccessBlock"}
GUARDDUTY_TYPES = {"Policy:S3/BucketBlockPublicAccessDisabled"}


def _csv_env(name: str) -> set[str]:
    raw = os.environ.get(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def bucket_names_from_event(event: dict[str, Any]) -> list[str]:
    """Return the bucket names an event refers to, or [] if it is not one we handle."""
    if not isinstance(event, dict):
        return []
    detail = event.get("detail")
    if not isinstance(detail, dict):
        return []

    source = event.get("source")
    if source == "aws.s3" and event.get("detail-type") == "AWS API Call via CloudTrail":
        if detail.get("eventName") not in CLOUDTRAIL_EVENT_NAMES:
            return []
        if detail.get("errorCode"):
            # The API call failed, so nothing changed.
            return []
        params = detail.get("requestParameters") or {}
        name = params.get("bucketName") if isinstance(params, dict) else None
        return [name] if isinstance(name, str) and name else []

    if source == "aws.guardduty" and event.get("detail-type") == "GuardDuty Finding":
        if detail.get("type") not in GUARDDUTY_TYPES:
            return []
        resource = detail.get("resource") or {}
        buckets = (resource.get("s3BucketDetails") or []) if isinstance(resource, dict) else []
        names = []
        for bucket in buckets:
            if isinstance(bucket, dict) and isinstance(bucket.get("name"), str) and bucket["name"]:
                names.append(bucket["name"])
        return sorted(set(names))

    return []


def current_block(s3: Any, bucket: str) -> dict[str, bool]:
    """Return the bucket's Block Public Access settings; missing config means all False."""
    try:
        resp = s3.get_public_access_block(Bucket=bucket)
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
            return {key: False for key in FULL_BLOCK}
        raise
    config = resp.get("PublicAccessBlockConfiguration", {})
    return {key: bool(config.get(key, False)) for key in FULL_BLOCK}


def remediate_bucket(s3: Any, bucket: str, *, exempt: set[str], dry_run: bool) -> dict[str, Any]:
    if bucket in exempt:
        return {"bucket": bucket, "action": "skipped_exempt"}
    before = current_block(s3, bucket)
    if before == FULL_BLOCK:
        return {"bucket": bucket, "action": "already_compliant"}
    if dry_run:
        return {"bucket": bucket, "action": "would_restore", "before": before}
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=dict(FULL_BLOCK))
    return {"bucket": bucket, "action": "restored", "before": before}


def lambda_handler(event: dict[str, Any], context: Any = None, s3: Any = None) -> dict[str, Any]:
    buckets = bucket_names_from_event(event)
    if not buckets:
        result = {"handled": False, "results": []}
        LOGGER.info(json.dumps(result))
        return result

    s3 = s3 or boto3.client("s3")
    exempt = _csv_env("EXEMPT_BUCKETS")
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    results = [remediate_bucket(s3, b, exempt=exempt, dry_run=dry_run) for b in buckets]
    result = {"handled": True, "dry_run": dry_run, "results": results}
    LOGGER.info(json.dumps(result))
    return result
