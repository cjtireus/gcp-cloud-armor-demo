#!/usr/bin/env bash
# =========================================================================
# logs.sh — what Cloud Armor actually did, read from Cloud Logging.
#
# WHERE CLOUD ARMOR LOGS LIVE
# There is no separate "Cloud Armor log". Its decisions are recorded as
# extra fields inside the LOAD BALANCER's request logs. Two consequences:
#
#   1. If request logging is disabled on the backend service, you get
#      nothing. 04-edge.sh enables it; the GCPBackendPolicy does the same
#      for the internal load balancer.
#   2. The log sampling rate applies. At 50% sampling you see half the
#      decisions. This demo uses 100% so nothing is missed.
#
# ENTRIES ARRIVE LATE. Up to about a minute. An empty result immediately
# after running attack.sh is normal — wait and run it again.
#
# THE KEY FIELDS
#   enforcedSecurityPolicy   the rule that was actually applied
#   previewSecurityPolicy    a preview-mode rule that WOULD have applied
#   preconfiguredExprIds     the exact OWASP signature that matched, e.g.
#                            owasp-crs-v042200-id942100-sqli. This is what
#                            you quote when tuning out a false positive.
#   matchedFieldName/Value   which part of the request carried the payload
#                            (only present with verbose logging on)
#
# Usage: ./logs.sh [--edge|--app|--preview|--all] [--limit N]
#   --edge     (default) denials by the edge policy: IP, geo, WAF
#   --app      app-tier policy: rate limiting outcomes
#   --preview  what preview-mode rules WOULD have blocked
#   --all      every request the edge policy evaluated, allowed or denied
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

MODE="edge"
LIMIT=20

while [[ $# -gt 0 ]]; do
  case "$1" in
    --edge)    MODE="edge"; shift ;;
    --app)     MODE="app"; shift ;;
    --preview) MODE="preview"; shift ;;
    --all)     MODE="all"; shift ;;
    --limit)   LIMIT="${2:?--limit needs a number}"; shift 2 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *)         die "unknown option: $1" ;;
  esac
done

# ---- Build the Cloud Logging filter --------------------------------------
# Logging filters are their own small query language: field=value terms,
# implicitly ANDed when separated by whitespace or newlines.
#
# `resource.type` is the single most important term, and the one most
# often got wrong — the external and internal load balancers log under
# DIFFERENT resource types, so a filter written for one silently returns
# nothing for the other.
case "$MODE" in
  edge)
    TITLE="Denials by the edge policy ($EDGE_POLICY)"
    # statusDetails narrows this to requests that were actually blocked.
    # Drop that line (or use --all) to see every evaluated request.
    FILTER="resource.type=\"http_load_balancer\"
            jsonPayload.enforcedSecurityPolicy.name=\"${EDGE_POLICY}\"
            jsonPayload.statusDetails=\"denied_by_security_policy\""
    ;;
  app)
    # The internal ALB logs under a different resource type than the edge one.
    TITLE="App-tier policy ($APP_POLICY) — rate limiting"
    FILTER="resource.type=\"internal_http_lb_rule\"
            jsonPayload.enforcedSecurityPolicy.name=\"${APP_POLICY}\""
    ;;
  preview)
    # Preview-mode matches are recorded under previewSecurityPolicy, a
    # separate field from the enforced one. In these entries the HTTP
    # status is 200 (nothing was blocked) while the preview field shows
    # the DENY that would have happened.
    TITLE="Preview mode — what these rules WOULD have blocked"
    FILTER="resource.type=\"http_load_balancer\"
            jsonPayload.previewSecurityPolicy.name=\"${EDGE_POLICY}\""
    ;;
  all)
    TITLE="Every request evaluated by the edge policy ($EDGE_POLICY)"
    FILTER="resource.type=\"http_load_balancer\"
            jsonPayload.enforcedSecurityPolicy.name=\"${EDGE_POLICY}\""
    ;;
esac

echo
echo "=============================================================================="
echo "  $TITLE"
echo "  last $LIMIT entries"
echo "=============================================================================="

RAW="$(gcloud logging read "$FILTER" --limit="$LIMIT" --format=json 2>/dev/null)"

if [[ -z "$RAW" || "$RAW" == "[]" ]]; then
  echo
  echo "  No entries."
  echo
  echo "  Load balancer logs reach Cloud Logging with up to a minute of lag, so an"
  echo "  empty result right after running attack.sh is normal — wait and retry."
  echo
  echo "  If it stays empty, check that request logging is on:"
  echo "    gcloud compute backend-services describe $EDGE_BACKEND --global \\"
  echo "      --format='value(logConfig.enable, logConfig.sampleRate)'"
  echo
  exit 0
fi

# jq renders this far more legibly than a gcloud format string can, but it is
# not guaranteed to be installed — fall back to a plain table.
if ! command -v jq &>/dev/null; then
  warn "jq not found; showing a reduced table (install jq for the full view)"
  echo "$RAW" | python3 -I "$HERE/format_logs.py" "$MODE"
  exit 0
fi

# In preview mode the enforced policy is just the default allow rule; the
# interesting detail is in previewSecurityPolicy, so prefer that one there.
echo "$RAW" | jq -r --arg mode "$MODE" '
  .[] |
  (if $mode == "preview"
     then (.jsonPayload.previewSecurityPolicy // .jsonPayload.enforcedSecurityPolicy // {})
     else (.jsonPayload.enforcedSecurityPolicy // .jsonPayload.previewSecurityPolicy // {})
   end) as $sp |
  [
    "",
    "  \(.timestamp[0:19])Z",
    "    client       \(.httpRequest.remoteIp // "?")",
    "    request      \(.httpRequest.requestMethod // "?") \(.httpRequest.requestUrl // "?" | .[0:100])",
    "    status       \(.httpRequest.status // "?")",
    "    policy       \($sp.name // "?")  priority \($sp.priority // "?")",
    "    action       \($sp.configuredAction // "?") → \($sp.outcome // "?")"
  ]
  + (if $sp.preconfiguredExprIds then
       ["    waf rule     \($sp.preconfiguredExprIds | join(", "))"] else [] end)
  + (if $sp.matchedFieldName then
       ["    matched      \($sp.matchedFieldType // "?") \"\($sp.matchedFieldName)\" = \"\($sp.matchedFieldValue // "")\""]
     elif $sp.matchedFieldType then
       ["    matched      \($sp.matchedFieldType)"] else [] end)
  + (if $sp.rateLimitAction then
       ["    rate limit   \($sp.rateLimitAction.outcome // "?")  key=\($sp.rateLimitAction.key // "-")"] else [] end)
  | .[]
'

echo
echo "------------------------------------------------------------------------------"
echo "  preconfiguredExprIds names the exact OWASP CRS signature that matched."
echo "  matched shows which request field carried the payload (verbose logging)."
echo "------------------------------------------------------------------------------"
echo
