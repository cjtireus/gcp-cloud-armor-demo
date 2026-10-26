#!/usr/bin/env python3
"""Fallback renderer for logs.sh when jq is not installed.

Reads the JSON array that `gcloud logging read --format=json` produces on
stdin and prints one block per Cloud Armor decision.
"""
import json
import sys


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "edge"
    try:
        entries = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"  could not parse log JSON: {exc}", file=sys.stderr)
        return 1

    for entry in entries:
        payload = entry.get("jsonPayload", {})
        # In preview mode the enforced policy is just the default allow
        # rule; the detail worth showing lives in previewSecurityPolicy.
        if mode == "preview":
            policy = (
                payload.get("previewSecurityPolicy")
                or payload.get("enforcedSecurityPolicy")
                or {}
            )
        else:
            policy = (
                payload.get("enforcedSecurityPolicy")
                or payload.get("previewSecurityPolicy")
                or {}
            )
        request = entry.get("httpRequest", {})

        print()
        print(f"  {entry.get('timestamp', '?')[:19]}Z")
        print(f"    client       {request.get('remoteIp', '?')}")
        print(
            f"    request      {request.get('requestMethod', '?')} "
            f"{str(request.get('requestUrl', '?'))[:100]}"
        )
        print(f"    status       {request.get('status', '?')}")
        print(
            f"    policy       {policy.get('name', '?')}  "
            f"priority {policy.get('priority', '?')}"
        )
        print(
            f"    action       {policy.get('configuredAction', '?')} "
            f"-> {policy.get('outcome', '?')}"
        )

        # Present only with preconfigured WAF rules: the exact OWASP CRS
        # signature that fired.
        expr_ids = policy.get("preconfiguredExprIds")
        if expr_ids:
            print(f"    waf rule     {', '.join(expr_ids)}")

        # Present only with verbose logging: which request field carried the
        # payload, and a prefix of its value.
        if policy.get("matchedFieldName"):
            print(
                f"    matched      {policy.get('matchedFieldType', '?')} "
                f"\"{policy['matchedFieldName']}\" = "
                f"\"{policy.get('matchedFieldValue', '')}\""
            )
        elif policy.get("matchedFieldType"):
            print(f"    matched      {policy['matchedFieldType']}")

        rate_limit = policy.get("rateLimitAction")
        if rate_limit:
            print(
                f"    rate limit   {rate_limit.get('outcome', '?')}  "
                f"key={rate_limit.get('key', '-')}"
            )

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
