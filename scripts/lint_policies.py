"""Render the example policies and lint each with parliament, offline.

parliament uses its bundled IAM action database, which can lag new AWS
actions. Known, reviewed findings are listed in ACCEPTED with the reason;
anything else makes the script exit 1.
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", message="pkg_resources is deprecated")

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from parliament import analyze_policy_string  # noqa: E402

from scs_lab.render import render_all  # noqa: E402

ACCEPTED = {
    # Key policies use "Resource": "*" to mean "this key"; parliament treats them like identity policies.
    ("kms-cloudtrail-key-policy", "RESOURCE_STAR"): "key policy Resource * means this key",
    # AWS's permission-boundary delegation examples use StringEquals with the boundary ARN.
    (
        "iam-role-creator",
        "MISMATCHED_TYPE_BUT_USABLE",
    ): "StringEquals on an ARN-typed key, as in AWS examples",
}


def main() -> int:
    unexpected = 0
    for path in render_all(REPO / "build" / "policies"):
        name = path.stem
        findings = analyze_policy_string(path.read_text(), include_community_auditors=False).findings
        print(f"{name}: {len(findings)} finding(s)")
        for f in findings:
            reason = ACCEPTED.get((name, f.issue))
            line = f.location.get("line") if isinstance(f.location, dict) else None
            tag = f"accepted: {reason}" if reason else "UNEXPECTED"
            print(f"  {f.issue} line {line} ({tag})")
            unexpected += 0 if reason else 1
    print(f"unexpected findings: {unexpected}")
    return 1 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
