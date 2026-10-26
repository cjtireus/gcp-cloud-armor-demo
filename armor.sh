#!/usr/bin/env bash
# =========================================================================
# armor.sh — the demo control panel. Creates and toggles Cloud Armor rules.
#
# HOW CLOUD ARMOR IS STRUCTURED
# A security POLICY is an ordered list of RULES, attached to a load
# balancer's backend service. For every request, Cloud Armor walks the
# rules from lowest priority number to highest, stops at the FIRST match,
# and applies that rule's action. If nothing matches, the default rule at
# the bottom decides.
#
# Each rule has:
#   priority    an integer; lower is evaluated first
#   match       either a list of source CIDRs, or a CEL-like expression
#   action      allow, deny-403 / deny-404 / deny-429 / deny-502,
#               throttle, rate-based-ban, or redirect
#   preview     if true, the rule is evaluated and LOGGED but not enforced
#
# THE TWO POLICIES IN THIS DEMO
#   EDGE_POLICY (global, on the edge load balancer)
#       IP denylist/allowlist, geo blocking, and the SQLi/XSS WAF.
#       Enforced at the Google edge nearest the client.
#
#   APP_POLICY (regional, on the GKE internal load balancer)
#       Rate limiting only. A regional INTERNAL Application Load Balancer
#       cannot enforce WAF rules, managed rules, body filtering, geography
#       or ASN — so this script refuses to put them there. See the guard in
#       app_rule_set() below; it is the most important safety check here.
#
# Usage: ./armor.sh <command> [args]     (no arguments prints help)
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# ---- Rule priorities -----------------------------------------------------
# Lower number is evaluated first, and the first match wins. Two
# consequences worth internalising:
#
#   1. An allow rule at priority 500 beats a deny at 1000. That is how
#      allowlisting works — allow the known-good source, then let the
#      default rule deny everyone else.
#   2. If a broad deny sits above a specific allow, the allow is dead code.
#      Ordering bugs are the most common Cloud Armor mistake.
#
# These are spaced in bands of 1000 so related rules can be slotted in
# later without renumbering. Hardcoding 1, 2, 3 is a trap you only regret
# once.
P_ALLOWLIST=500      # edge: allow listed CIDRs (allowlist mode only)
P_DENYLIST=1000      # edge: deny listed CIDRs
P_GEO=1100           # edge: deny by region code
P_WAF_SQLI=2000      # edge: preconfigured SQLi rule set
P_WAF_XSS=2100       # edge: preconfigured XSS rule set
# These two are ordered specific-before-general, and it matters.
#
# The throttle rule matches --src-ip-ranges="*", i.e. EVERY request. If it
# sat above the ban rule, it would match /login first and the ban rule
# below could never fire — unreachable dead code, with no error anywhere
# to tell you. (That is exactly what happened in an earlier version of
# this demo: 195 log entries, every one of them rule 3000, zero bans.)
#
# General principle for any policy engine with first-match-wins ordering:
# the narrower the match, the higher it goes.
P_BAN=3000           # app:  rate-based ban on BAN_PATH only  (specific)
P_THROTTLE=3100      # app:  throttle every other request     (catch-all)
P_DEFAULT=2147483647 # the default rule. This is 2^31-1, the maximum int32,
                     # so nothing can ever sort below it. Every policy has
                     # one; it can be UPDATED but never deleted.

# ---- The WAF expressions -------------------------------------------------
# `evaluatePreconfiguredWaf()` pulls in an entire Google-maintained rule set
# derived from the OWASP Core Rule Set, rather than you writing signatures
# by hand. Each set contains dozens of individual signatures.
#
# Two parts of the name matter:
#
#   v422     the CRS version — 4.22. This moves over time, and most blog
#            posts and older tutorials still show v33. config.env pins it,
#            and cmd_create verifies the pinned version actually exists.
#
#   stable   as opposed to `canary`, which carries newer, less-proven
#            signatures.
#
# `sensitivity` selects how many signatures are active, 0 through 4. Higher
# catches more attacks and produces more false positives. Level 1 is the
# conservative starting point and still blocks every payload in attack.sh.
# You can also opt individual signatures in or out by ID — that is how you
# fix a false positive without disabling the whole set.
SQLI_EXPR="evaluatePreconfiguredWaf('sqli-${WAF_RULESET_VERSION}-stable', {'sensitivity': ${WAF_SENSITIVITY}})"
XSS_EXPR="evaluatePreconfiguredWaf('xss-${WAF_RULESET_VERSION}-stable', {'sensitivity': ${WAF_SENSITIVITY}})"

# =========================================================================
# Rule helpers
#
# Note the one difference between the edge and app variants throughout:
# the app ones pass `--region="$REGION"`. A security policy is either
# global or regional, and gcloud needs to know which you mean. There is no
# `--global` flag on the `rules` subcommands — omitting --region IS global.
# (You will find `--global-security-policy` in some documentation; it does
# not exist in the current CLI.)
# =========================================================================

# Does a rule exist at this priority? Same describe-exits-nonzero trick as
# the exists_* helpers in lib.sh.
edge_rule_exists() {
  gcloud compute security-policies rules describe "$1" \
    --security-policy="$EDGE_POLICY" &>/dev/null
}

app_rule_exists() {
  gcloud compute security-policies rules describe "$1" \
    --security-policy="$APP_POLICY" --region="$REGION" &>/dev/null
}

# Delete a rule if present. Checking first means deleting an absent rule is
# a silent no-op rather than an error, so `reset` can run on a clean policy.
# `--quiet` suppresses gcloud's interactive "are you sure?" prompt, which
# would otherwise hang a non-interactive script forever.
edge_rule_delete() {
  edge_rule_exists "$1" || return 0
  gcloud compute security-policies rules delete "$1" \
    --security-policy="$EDGE_POLICY" --quiet >/dev/null 2>&1
}

app_rule_delete() {
  app_rule_exists "$1" || return 0
  gcloud compute security-policies rules delete "$1" \
    --security-policy="$APP_POLICY" --region="$REGION" --quiet >/dev/null 2>&1
}

# edge_rule_set PRIORITY <gcloud args...>
#
# Delete-then-create rather than `rules update`. Update only modifies the
# fields you pass and leaves the rest as they were, so toggling a rule
# between two shapes can leave stale settings behind — for instance a
# `--preview` flag from a previous call that you did not think to clear.
# Deleting first guarantees the rule ends up exactly as specified.
#
# "$@" forwards every remaining argument to gcloud untouched, which is what
# lets callers pass arbitrary flags like --expression or --src-ip-ranges.
edge_rule_set() {
  local prio="$1"; shift
  edge_rule_delete "$prio"
  gcloud compute security-policies rules create "$prio" \
    --security-policy="$EDGE_POLICY" "$@" >/dev/null
}

# app_rule_set PRIORITY <gcloud args...>
#
# ===================== THE MOST IMPORTANT GUARD HERE =====================
# Same as edge_rule_set, but it first inspects the arguments and refuses
# anything a regional INTERNAL load balancer cannot enforce.
#
# Why bother? Because Google Cloud will happily accept these rules. The
# API call succeeds, the rule appears in `armor.sh status`, the
# GCPBackendPolicy reports `Attached: True` — and the rule never fires.
# There is no error, no warning, nothing in the logs. You would be left
# believing an application has WAF protection that it does not have.
#
# An error you can see beats a silent gap you cannot. So this fails loudly
# instead.
#
# The `case` patterns match substrings (`*foo*`) against each argument:
#   evaluatePreconfiguredWaf / evaluateManagedRules   WAF rule sets
#   request.body                                      body inspection
#   origin.region_code                                geography
#   origin.asn                                        autonomous system
# =========================================================================
app_rule_set() {
  local prio="$1"; shift
  local arg
  for arg in "$@"; do
    case "$arg" in
      *evaluatePreconfiguredWaf*|*evaluateManagedRules*|*request.body*|*origin.region_code*|*origin.asn*)
        die "Refusing to add this rule to the regional policy '$APP_POLICY'.

  A regional INTERNAL Application Load Balancer cannot enforce WAF rules,
  managed rules, body filtering, geography or ASN. The rule would attach
  without error, report Attached: True, and never fire.

  These belong in the edge policy '$EDGE_POLICY'. See README.md."
        ;;
    esac
  done
  app_rule_delete "$prio"
  gcloud compute security-policies rules create "$prio" \
    --security-policy="$APP_POLICY" --region="$REGION" "$@" >/dev/null
}

# Detect the caller's public IP, or explain why the demo needs it.
require_my_ip() {
  local ip
  ip="$(my_public_ip)" \
    || die "Could not detect your public IP, and this command needs it to avoid locking you out."
  echo "$ip"
}

# =========================================================================
# Commands
# =========================================================================

# Create both policies and the baseline rules. Run this BEFORE 02-app.sh,
# because the GCPBackendPolicy manifest references the regional policy by
# name and attaching a non-existent policy fails.
cmd_create() {
  say "Edge policy — $EDGE_POLICY (global)"
  if exists_policy "$EDGE_POLICY"; then
    ok "$EDGE_POLICY already exists"
  else
    # No --region, so this is a global policy, usable by global load
    # balancers. --type=CLOUD_ARMOR is the default backend policy type;
    # the alternatives are CLOUD_ARMOR_EDGE (for CDN-cached content, which
    # supports fewer features) and CLOUD_ARMOR_INTERNAL_SERVICE.
    gcloud compute security-policies create "$EDGE_POLICY" \
      --type=CLOUD_ARMOR \
      --description="Cloud Armor demo — edge: IP denylist/allowlist, geo, WAF" >/dev/null \
      || die "failed to create $EDGE_POLICY"
    ok "created $EDGE_POLICY"
  fi

  # Verbose logging is what makes ./logs.sh genuinely useful. At the
  # default NORMAL level a blocked request logs only the rule priority and
  # signature ID. At VERBOSE it also records WHICH request field carried
  # the payload and a prefix of its value — the difference between "rule
  # 2000 matched" and "the `q` parameter contained ' OR 1=1 --".
  #
  # The trade-off: those snippets are real request data, so verbose logging
  # can put user input, and potentially sensitive values, into your logs.
  # Google's guidance is to enable it while building and tuning rules, then
  # turn it off for steady-state production.
  gcloud compute security-policies update "$EDGE_POLICY" \
    --log-level=VERBOSE >/dev/null 2>&1 \
    && ok "verbose logging enabled" || warn "could not set verbose logging"

  say "App policy — $APP_POLICY (regional, $REGION)"
  if exists_policy "$APP_POLICY" "$REGION"; then
    ok "$APP_POLICY already exists"
  else
    gcloud compute security-policies create "$APP_POLICY" \
      --type=CLOUD_ARMOR \
      --region="$REGION" \
      --description="Cloud Armor demo — app tier: rate limiting (internal ALB: no WAF)" >/dev/null \
      || die "failed to create $APP_POLICY"
    ok "created $APP_POLICY"
  fi

  # Rule set versions change as the OWASP Core Rule Set advances, and a
  # typo or a stale version produces an unhelpful error at rule-creation
  # time. Checking up front, and printing what IS available, turns that
  # into a one-line fix. `list-preconfigured-expression-sets` is a useful
  # command to remember — it is how you discover what your project offers.
  say "Verifying the WAF rule set version"
  if gcloud compute security-policies list-preconfigured-expression-sets \
       --format="value(id)" 2>/dev/null | grep -q "sqli-${WAF_RULESET_VERSION}-stable"; then
    ok "sqli-${WAF_RULESET_VERSION}-stable is available"
  else
    warn "sqli-${WAF_RULESET_VERSION}-stable not found. Available sets:"
    gcloud compute security-policies list-preconfigured-expression-sets \
      --format="value(id)" 2>/dev/null | grep -E '^(sqli|xss)' | sed 's/^/    /'
    die "Set WAF_RULESET_VERSION in config.env to a version listed above."
  fi

  say "Baseline rules"
  cmd_waf on
  cmd_ratelimit on
  echo
  ok "Policies ready. Default action is allow; nothing is blocked until you toggle a rule."
  echo
  echo "Try:  ./armor.sh status"
}

# ./armor.sh waf [on|off|preview]
#
# The centrepiece of the demo. `preview` is the one worth understanding:
# a rule marked --preview is fully evaluated and logged, but the action is
# NOT applied. Requests that would have been blocked sail through with a
# 200, while the log records exactly what would have happened.
#
# That is how you actually deploy a WAF in front of a live application.
# Turning signatures straight on in enforcing mode will eventually block
# legitimate traffic you did not anticipate. The real-world sequence is:
# enable in preview, run against production traffic for days, review what
# it would have blocked, opt out the false positives by signature ID, then
# flip to enforcing.
cmd_waf() {
  local mode="${1:-on}"
  # An empty bash array. Later expanded as "${preview_flag[@]}", which
  # contributes zero arguments when empty and `--preview` when not. This
  # is the clean way to build an optional flag; interpolating a string
  # variable would pass an empty argument that gcloud rejects.
  local preview_flag=()

  case "$mode" in
    on)      ;;
    off)     say "WAF off"
             edge_rule_delete "$P_WAF_SQLI"; edge_rule_delete "$P_WAF_XSS"
             ok "removed SQLi and XSS rules — attacks will now reach the pod"
             await_edge 200 "${WAF_CANARY[@]}"
             await_edge 200 "${XSS_CANARY[@]}"
             return 0 ;;
    preview) preview_flag=(--preview)
             shift || true ;;
    *)       die "usage: armor.sh waf [on|off|preview]" ;;
  esac

  exists_policy "$EDGE_POLICY" || die "Run ./armor.sh create first."

  if [[ ${#preview_flag[@]} -gt 0 ]]; then
    say "WAF in preview mode"
  else
    say "WAF on"
  fi

  edge_rule_set "$P_WAF_SQLI" \
    --expression="$SQLI_EXPR" \
    --action=deny-403 \
    --description="WAF: SQL injection (OWASP CRS ${WAF_RULESET_VERSION}, sensitivity ${WAF_SENSITIVITY})" \
    "${preview_flag[@]}"
  ok "rule $P_WAF_SQLI — SQLi"

  edge_rule_set "$P_WAF_XSS" \
    --expression="$XSS_EXPR" \
    --action=deny-403 \
    --description="WAF: cross-site scripting (OWASP CRS ${WAF_RULESET_VERSION}, sensitivity ${WAF_SENSITIVITY})" \
    "${preview_flag[@]}"
  ok "rule $P_WAF_XSS — XSS"

  # Enforcing rules block the canary; preview rules let it through while
  # still logging. Either way, wait for the change to actually be live.
  if [[ ${#preview_flag[@]} -eq 0 ]]; then
    await_edge 403 "${WAF_CANARY[@]}"
    await_edge 403 "${XSS_CANARY[@]}"
  else
    await_edge 200 "${WAF_CANARY[@]}"
    await_edge 200 "${XSS_CANARY[@]}"
  fi

  if [[ ${#preview_flag[@]} -gt 0 ]]; then
    echo
    echo "  Preview mode logs what these rules WOULD block without enforcing them."
    echo "  Attacks will still return 200. See them with: ./logs.sh --preview"
  fi
}

# ./armor.sh denylist [on|off]
#
# The simplest kind of Cloud Armor rule: match on source address, deny.
# No request inspection at all — the decision is made from the IP alone,
# before anything looks at the URL, headers or body. That makes it the
# cheapest rule type and the right tool for blocking a known-bad source.
#
# --src-ip-ranges takes a comma-separated list of CIDRs. A single address
# is written as a /32 (IPv4) or /128 (IPv6).
cmd_denylist() {
  local mode="${1:-on}"
  exists_policy "$EDGE_POLICY" || die "Run ./armor.sh create first."

  if [[ "$mode" == "off" ]]; then
    say "IP denylist off"
    edge_rule_delete "$P_DENYLIST"
    ok "removed rule $P_DENYLIST"
    return 0
  fi

  [[ -n "$DENY_CIDRS" ]] || die "DENY_CIDRS is empty in config.env."
  say "IP denylist on"
  edge_rule_set "$P_DENYLIST" \
    --src-ip-ranges="$DENY_CIDRS" \
    --action=deny-403 \
    --description="L3/L4: denylisted CIDRs"
  ok "rule $P_DENYLIST — denying $DENY_CIDRS"
}

# ./armor.sh deny-me
#
# Adds YOUR public IP to the denylist so the effect is visible immediately
# from the machine you are demoing on. Without this you would be blocking
# an address you cannot send traffic from, and nothing visible happens.
cmd_deny_me() {
  exists_policy "$EDGE_POLICY" || die "Run ./armor.sh create first."
  local ip; ip="$(require_my_ip)"

  say "Denylisting your own IP"
  # Keeps the configured demo CIDRs in place and adds yours alongside.
  local ranges="${ip}/32"
  [[ -n "$DENY_CIDRS" ]] && ranges="${DENY_CIDRS},${ip}/32"

  edge_rule_set "$P_DENYLIST" \
    --src-ip-ranges="$ranges" \
    --action=deny-403 \
    --description="L3/L4: denylisted CIDRs (includes the demo operator)"
  ok "rule $P_DENYLIST now denies $ip"
  await_edge 403
  echo
  echo "  Every request from you should now return 403, even benign ones."
  echo "  Try:  ./attack.sh baseline"
  echo "  Undo: ./armor.sh undeny-me"
}

cmd_undeny_me() {
  say "Restoring the denylist to its configured CIDRs"
  if [[ -n "$DENY_CIDRS" ]]; then
    edge_rule_set "$P_DENYLIST" \
      --src-ip-ranges="$DENY_CIDRS" \
      --action=deny-403 \
      --description="L3/L4: denylisted CIDRs"
    ok "rule $P_DENYLIST reset to $DENY_CIDRS"
    await_edge 200
  else
    edge_rule_delete "$P_DENYLIST"
    ok "removed rule $P_DENYLIST"
  fi
}

# ./armor.sh allowlist [on|off]
#
# Inverts the policy's posture. Instead of "allow everything, deny these",
# it becomes "deny everything, allow only these". Two changes are needed,
# and both matter:
#
#   1. an allow rule at priority 500 for the permitted CIDRs
#   2. the DEFAULT rule, at the bottom, flipped from allow to deny-403
#
# Step 2 is the one people forget. Adding an allow rule on its own changes
# nothing, because the default rule still permits everyone else. The
# default rule cannot be deleted, only updated — which is why this uses
# `rules update` rather than the delete-then-create helper.
#
# This is the one command here that can lock you out of your own load
# balancer, so it always adds your current public IP to the allow list.
cmd_allowlist() {
  local mode="${1:-on}"
  exists_policy "$EDGE_POLICY" || die "Run ./armor.sh create first."

  if [[ "$mode" == "off" ]]; then
    say "Allowlist mode off"
    edge_rule_delete "$P_ALLOWLIST"
    gcloud compute security-policies rules update "$P_DEFAULT" \
      --security-policy="$EDGE_POLICY" \
      --action=allow >/dev/null \
      || die "failed to restore the default rule"
    ok "default rule back to allow"
    return 0
  fi

  # Default-deny is the one setting in this demo that can lock the operator
  # out of their own load balancer. Always include the caller.
  local ip; ip="$(require_my_ip)"
  local ranges="${ip}/32"
  [[ -n "$ALLOW_CIDRS" ]] && ranges="${ALLOW_CIDRS},${ip}/32"

  say "Allowlist mode on"
  edge_rule_set "$P_ALLOWLIST" \
    --src-ip-ranges="$ranges" \
    --action=allow \
    --description="L3/L4: allowlisted CIDRs"
  ok "rule $P_ALLOWLIST — allowing $ranges"

  gcloud compute security-policies rules update "$P_DEFAULT" \
    --security-policy="$EDGE_POLICY" \
    --action=deny-403 >/dev/null \
    || die "failed to flip the default rule to deny"
  ok "default rule flipped to deny-403"
  echo
  echo "  Everything except $ranges now gets a 403."
  echo "  Undo: ./armor.sh allowlist off"
}

# ./armor.sh geo [COUNTRY_CODE|off]
#
# Blocks a country using a rule EXPRESSION rather than a CIDR list. The
# expression language is CEL-like; `origin.region_code` is resolved by
# Cloud Armor from Google's own IP geolocation database.
#
# Be honest about what this is for. The database is updated roughly weekly
# and rolls out gradually, and anyone determined can use a VPN. Geo rules
# are a compliance and content-licensing tool, not a security boundary.
cmd_geo() {
  local cc="${1:-}"
  exists_policy "$EDGE_POLICY" || die "Run ./armor.sh create first."

  if [[ "$cc" == "off" ]]; then
    say "Geo blocking off"
    edge_rule_delete "$P_GEO"
    ok "removed rule $P_GEO"
    await_edge 200
    return 0
  fi

  # Default to the operator's own country so the block is demonstrable live.
  if [[ -z "$cc" ]]; then
    cc="${GEO_CC:-}"
    [[ -n "$cc" ]] || cc="$(my_region_code)" \
      || die "Could not detect your region code. Pass one: ./armor.sh geo SE"
  fi

  say "Geo blocking — $cc"
  edge_rule_set "$P_GEO" \
    --expression="origin.region_code == '${cc}'" \
    --action=deny-403 \
    --description="L7: deny requests originating in ${cc}"
  ok "rule $P_GEO — denying traffic from $cc"

  # await_edge probes from THIS machine, so what counts as "the rule is
  # live" depends on whether this machine is the one being blocked.
  #
  # Getting this wrong is subtle and produces confidently wrong results:
  # an earlier version always waited for 403, so when blocking a DIFFERENT
  # country it saw the previous rule still returning 403, declared success
  # and returned while the new rule was not yet live. The caller then
  # tested a stale policy.
  #
  # Blocking my own country  → expect this machine to start getting 403.
  # Blocking another country → expect this machine to be allowed, so wait
  #                            for 200. If a previous rule was blocking us,
  #                            that transition is exactly the right signal.
  local my_cc; my_cc="$(my_region_code 2>/dev/null)" || my_cc=""
  if [[ -n "$my_cc" && "$cc" == "$my_cc" ]]; then
    await_edge 403
  else
    await_edge 200
    echo
    echo "  Note: $cc is not your country, so this machine stays allowed."
    echo "  Verify the block from an origin in $cc — ./attack.sh geo uses"
    echo "  the probe VM from ./05-geo-probe.sh for exactly this."
  fi

  echo
  echo "  Note: geo rules work at the edge only. The app-tier policy cannot"
  echo "  match on geography, and PSC hides the client IP from it anyway."
}

# ./armor.sh ratelimit [on|off]
#
# The only rules that live on the APP policy, because rate limiting is one
# of the few things a regional internal load balancer can enforce.
#
# TWO ACTIONS, OFTEN CONFUSED
#   throttle         caps the rate. Requests over the limit get the
#                    exceed-action, but the moment the client slows down
#                    they are served normally again.
#   rate-based-ban   same, plus: once a client crosses the threshold it is
#                    blocked outright for ban-duration-sec, even if it
#                    stops sending traffic. Harsher, and right for things
#                    like credential stuffing against a login endpoint.
#
# A rate limit rule has two actions, not one:
#   --conform-action   what happens UNDER the limit  (must be allow)
#   --exceed-action    what happens OVER it          (deny-429 here; 429
#                      is "Too Many Requests", the honest status code)
cmd_ratelimit() {
  local mode="${1:-on}"
  exists_policy "$APP_POLICY" "$REGION" || die "Run ./armor.sh create first."

  if [[ "$mode" == "off" ]]; then
    say "Rate limiting off"
    app_rule_delete "$P_THROTTLE"; app_rule_delete "$P_BAN"
    ok "removed rules $P_THROTTLE and $P_BAN"
    return 0
  fi

  say "Rate limiting on (app tier, $APP_POLICY)"

  # ---- Why --enforce-on-key matters more than the threshold ----
  #
  # "20 requests per 60 seconds" is meaningless until you say per WHAT.
  # enforce-on-key answers that: per client IP, per cookie, per header,
  # per URL path, or `all` for one shared bucket across every client.
  #
  # Here the obvious choice, `ip`, would be badly wrong. Traffic reaches
  # this tier through Private Service Connect, which source-NATs every
  # request onto an address from the PSC NAT subnet. From the internal
  # load balancer's point of view, the entire internet is a handful of
  # Google proxy addresses. Keying on `ip` would therefore lump all users
  # into one bucket, and a single busy client would throttle everybody.
  #
  # `xff-ip` reads the originating address out of the X-Forwarded-For
  # header that the edge load balancer sets, recovering the real client.
  # You can see both in `./logs.sh --app`: `client` is the proxy address,
  # `key=` is the actual user.
  #
  # Note these values are lowercase. Documentation often shows XFF-IP; the
  # CLI only accepts xff-ip.
  #
  # The fallback below exists because feature support varies by policy
  # type, and a demo that dies on an unsupported flag is worse than one
  # that degrades and says so.
  local key="xff-ip"
  if ! app_rule_set "$P_THROTTLE" \
        --src-ip-ranges="*" \
        --action=throttle \
        --rate-limit-threshold-count="$RATE_LIMIT_COUNT" \
        --rate-limit-threshold-interval-sec="$RATE_LIMIT_INTERVAL" \
        --conform-action=allow \
        --exceed-action=deny-429 \
        --enforce-on-key="$key" \
        --description="Throttle: ${RATE_LIMIT_COUNT} req / ${RATE_LIMIT_INTERVAL}s per client" 2>/dev/null
  then
    warn "enforce-on-key=xff-ip rejected; falling back to ip"
    warn "(all clients will share the PSC NAT addresses — see README)"
    key="ip"
    app_rule_set "$P_THROTTLE" \
      --src-ip-ranges="*" \
      --action=throttle \
      --rate-limit-threshold-count="$RATE_LIMIT_COUNT" \
      --rate-limit-threshold-interval-sec="$RATE_LIMIT_INTERVAL" \
      --conform-action=allow \
      --exceed-action=deny-429 \
      --enforce-on-key="$key" \
      --description="Throttle: ${RATE_LIMIT_COUNT} req / ${RATE_LIMIT_INTERVAL}s per client" \
      || die "failed to create the throttle rule"
  fi
  ok "rule $P_THROTTLE — throttle ${RATE_LIMIT_COUNT}/${RATE_LIMIT_INTERVAL}s (key=$key)"

  app_rule_set "$P_BAN" \
    --expression="request.path.matches('${BAN_PATH}')" \
    --action=rate-based-ban \
    --rate-limit-threshold-count="$BAN_COUNT" \
    --rate-limit-threshold-interval-sec="$BAN_INTERVAL" \
    --ban-duration-sec="$BAN_DURATION" \
    --conform-action=allow \
    --exceed-action=deny-429 \
    --enforce-on-key="$key" \
    --description="Rate-based ban on ${BAN_PATH}: ${BAN_COUNT}/${BAN_INTERVAL}s, ban ${BAN_DURATION}s" \
    || warn "could not create the rate-based ban rule"
  ok "rule $P_BAN — ban on $BAN_PATH"

  # The edge toggles call await_edge to block until the change is live.
  # There is no equivalent here, and deliberately so: the only way to
  # probe an app-tier rule is to send traffic through it, and doing that
  # repeatedly would trip the very rate limit we are waiting on. So warn
  # instead of polling.
  echo
  echo "  These rules take 1-3 minutes to propagate. Testing immediately"
  echo "  will exercise the OLD configuration — wait before ./attack.sh flood."
  echo
  echo "  Check which rule actually fires with ./logs.sh --app:"
  echo "    $P_BAN should show RATE_BASED_BAN on $BAN_PATH"
  echo "    $P_THROTTLE should show THROTTLE on everything else"
}

# ./armor.sh reset — back to "allow everything", for a clean demo start.
cmd_reset() {
  say "Resetting both policies to baseline"

  for p in "$P_ALLOWLIST" "$P_DENYLIST" "$P_GEO" "$P_WAF_SQLI" "$P_WAF_XSS"; do
    edge_rule_delete "$p" && ok "removed edge rule $p" || true
  done

  # The default rule cannot be deleted, only updated.
  gcloud compute security-policies rules update "$P_DEFAULT" \
    --security-policy="$EDGE_POLICY" \
    --action=allow >/dev/null 2>&1 \
    && ok "default rule set to allow" || true

  for p in "$P_THROTTLE" "$P_BAN"; do
    app_rule_delete "$p" && ok "removed app rule $p" || true
  done

  echo
  ok "Baseline: everything allowed."
}

# ./armor.sh status — print every rule and where each policy is attached.
#
# The first thing to run when a rule is not behaving as expected. Check
# the priority ordering before anything else: a deny above an allow makes
# the allow unreachable, and that explains most surprises.
cmd_status() {
  local ip cc
  ip="$(my_public_ip 2>/dev/null)" || ip="unknown"
  cc="$(my_region_code 2>/dev/null)" || cc="unknown"

  echo
  echo "=============================================================================="
  echo "  Cloud Armor demo status"
  echo "  project $PROJECT_ID   region $REGION"
  echo "  your IP $ip   region code $cc"
  local eip; eip="$(edge_ip 2>/dev/null)"
  [[ -n "$eip" ]] && echo "  edge    http://${eip}/"
  echo "=============================================================================="

  echo
  echo "POLICY 1  $EDGE_POLICY  (global, on the edge load balancer)"
  echo "          IP rules, geo and WAF. Enforced at the Google edge."
  echo "------------------------------------------------------------------------------"
  if exists_policy "$EDGE_POLICY"; then
    # There is no `gcloud compute security-policies rules list` subcommand,
    # which surprises most people. Rules live inside the policy object, so
    # you fetch the policy and unpack them.
    #
    # `--flatten="rules[]"` turns one record containing a list of rules
    # into one record per rule, so the table formatter can print a row for
    # each. Without it you would get a single row with the whole list
    # crammed into one cell. This flatten-then-format pattern works for
    # any nested list in a gcloud response and is worth remembering.
    gcloud compute security-policies describe "$EDGE_POLICY" --global \
      --flatten="rules[]" \
      --format="table[box](
          rules.priority:label=PRIORITY,
          rules.action:label=ACTION,
          rules.preview:label=PREVIEW,
          rules.description:label=DESCRIPTION)" 2>/dev/null
  else
    echo "  not created — run ./armor.sh create"
  fi

  echo
  echo "POLICY 2  $APP_POLICY  (regional $REGION, on the GKE internal ALB)"
  echo "          Rate limiting only. Internal ALBs cannot enforce WAF rules."
  echo "------------------------------------------------------------------------------"
  if exists_policy "$APP_POLICY" "$REGION"; then
    gcloud compute security-policies describe "$APP_POLICY" --region="$REGION" \
      --flatten="rules[]" \
      --format="table[box](
          rules.priority:label=PRIORITY,
          rules.action:label=ACTION,
          rules.preview:label=PREVIEW,
          rules.description:label=DESCRIPTION)" 2>/dev/null
  else
    echo "  not created — run ./armor.sh create"
  fi

  echo
  echo "ATTACHMENTS"
  echo "------------------------------------------------------------------------------"
  local attached
  attached="$(gcloud compute backend-services describe "$EDGE_BACKEND" --global \
    --format="value(securityPolicy.basename())" 2>/dev/null)"
  printf "  edge backend service  %-24s %s\n" "$EDGE_BACKEND" "${attached:-<none>}"

  if kubectl get ns "$APP_NAMESPACE" &>/dev/null; then
    local st
    st="$(kubectl -n "$APP_NAMESPACE" get gcpbackendpolicy "${APP_NAME}-armor" \
      -o jsonpath='{.status.conditions[?(@.type=="Attached")].status}' 2>/dev/null)"
    printf "  GCPBackendPolicy      %-24s Attached=%s\n" "${APP_NAME}-armor" "${st:-unknown}"
  fi
  echo
}

usage() {
  cat <<EOF

armor.sh — Cloud Armor demo control panel

  create                 Create both policies and the baseline rules
  status                 Show every rule and where each policy is attached
  reset                  Remove all demo rules; allow everything

 Edge policy ($EDGE_POLICY) — enforced at the Google edge
  waf on|off             SQLi + XSS preconfigured WAF rules
  waf preview            Log what the WAF would block, without enforcing
  denylist on|off        Deny the CIDRs in DENY_CIDRS
  deny-me                Add your own public IP to the denylist
  undeny-me              Remove it again
  allowlist on|off       Flip the default rule to deny; allow only your IP
  geo [CC|off]           Deny a country by region code (defaults to yours)

 App policy ($APP_POLICY) — enforced at the GKE internal ALB
  ratelimit on|off       Throttle + rate-based ban

 Notes
  WAF rules exist only in the edge policy. A regional internal Application
  Load Balancer cannot enforce them, so this script refuses to add them to
  the app policy — see README.md.

EOF
}

# =========================================================================
# Command dispatcher.
#
# "${1:-}" is the first argument, or empty if none was given — the `:-`
# prevents `set -u` from aborting on an unset variable. Each branch
# `shift`s to drop the command name, so "$@" passed to the function is
# just the remaining arguments.
#
# This case/shift pattern is the standard way to give a shell script
# subcommands, and it scales a lot better than a pile of if/elif.
# =========================================================================
case "${1:-}" in
  create)     shift; cmd_create "$@" ;;
  status)     shift; cmd_status "$@" ;;
  reset)      shift; cmd_reset "$@" ;;
  waf)        shift; cmd_waf "$@" ;;
  denylist)   shift; cmd_denylist "$@" ;;
  deny-me)    shift; cmd_deny_me "$@" ;;
  undeny-me)  shift; cmd_undeny_me "$@" ;;
  allowlist)  shift; cmd_allowlist "$@" ;;
  geo)        shift; cmd_geo "$@" ;;
  ratelimit)  shift; cmd_ratelimit "$@" ;;
  ""|-h|--help|help) usage ;;
  *)          echo "unknown command: $1" >&2; usage; exit 1 ;;
esac
