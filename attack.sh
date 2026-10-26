#!/usr/bin/env bash
# =========================================================================
# attack.sh — fire labelled requests at the edge and tabulate what happened.
#
# IS THIS SAFE TO RUN? Yes. Every payload is a textbook OWASP example sent
# to your own demo load balancer, and the backend is a stock Google sample
# that only echoes what it received. There is no database, no shell, and
# nothing to inject into. The question the script answers is not "can the
# app be exploited" but "which of these does Cloud Armor stop before they
# arrive".
#
# READ THIS IF RESULTS LOOK WRONG. Cloud Armor rule changes take 1-3
# minutes to reach the edge. If you toggled a rule and immediately ran
# this, you may be testing the old policy. The armor.sh toggles already
# wait for propagation; if you changed something in the console instead,
# give it a few minutes.
#
# Usage: ./attack.sh [scenario ...]
#   baseline  benign traffic that should always pass
#   sqli      SQL injection payloads
#   xss       cross-site scripting payloads
#   denylist  benign request, to show an IP block hitting everything
#   geo       benign request, to show a geo block
#   flood     burst traffic to trip the app-tier rate limit
#   ban       prove the rate-based ban persists after traffic stops
#   all       default. baseline + sqli + xss ONLY — flood and ban are
#             excluded because they leave you blocked for minutes and
#             would break every scenario after them.
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

EDGE_IP="$(require_edge_ip)"
BASE="http://${EDGE_IP}"

# Running totals, printed as a summary at the end. The script exits
# non-zero if anything did not match expectations, so it can be used in CI
# as a regression test on the policy, not just as a demo prop.
PASS=0; FAIL=0

hr()  { printf '%s\n' "------------------------------------------------------------------------------------------"; }
hdr() {
  echo
  printf '%s\n' "=========================================================================================="
  printf '  %s\n' "$1"
  printf '%s\n' "=========================================================================================="
  printf '%-34s %-34s %-7s %-6s %s\n' "SCENARIO" "PAYLOAD" "EXPECT" "GOT" ""
  hr
}

# probe <label> <expected-code> "q=<payload>"
#
# Sends one request carrying the payload as a query parameter, then
# compares the status code against what was expected.
#
# Two curl details that matter:
#
#   --data-urlencode  percent-encodes the payload. Essential: these
#                     payloads contain spaces, quotes, angle brackets and
#                     ampersands, all of which would otherwise break the
#                     URL or be silently truncated. Encoding does not help
#                     the attacker evade the WAF — Cloud Armor decodes
#                     before inspecting, which is exactly what you want it
#                     to do.
#
#   --get             forces the encoded data into the query string of a
#                     GET rather than sending it as a POST body.
#
# `${path#*=}` strips everything up to and including the first `=`, so
# "q=<script>..." yields just the payload. `#` is bash prefix removal.
probe() {
  local label="$1" expect="$2" path="$3"
  local code shown

  # -o /dev/null discards the body; -w '%{http_code}' prints only the
  # status code. That is the entire signal we need.
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --get \
            --data-urlencode "q=${path#*=}" "${BASE}/" 2>/dev/null)"

  shown="${path:0:33}"
  local verdict
  if [[ "$code" == "$expect" ]]; then
    PASS=$(( PASS + 1 ))
    if [[ "$code" == "403" ]]; then verdict="✓ BLOCKED"
    elif [[ "$code" == "429" ]]; then verdict="✓ THROTTLED"
    else verdict="✓"; fi
  else
    FAIL=$(( FAIL + 1 ))
    verdict="✗ expected $expect"
  fi
  printf '%-34s %-34s %-7s %-6s %s\n' "$label" "$shown" "$expect" "$code" "$verdict"
}

# raw_probe <label> <expected-code> <full-path>
#
# For requests where the PATH is the point ("/", "/healthz") rather than a
# query payload. Keeps the path verbatim instead of folding it into a q=
# parameter.
raw_probe() {
  local label="$1" expect="$2" path="$3"
  local code verdict
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${BASE}${path}" 2>/dev/null)"
  if [[ "$code" == "$expect" ]]; then
    PASS=$(( PASS + 1 )); verdict="✓"
    [[ "$code" == "403" ]] && verdict="✓ BLOCKED"
  else
    FAIL=$(( FAIL + 1 )); verdict="✗ expected $expect"
  fi
  printf '%-34s %-34s %-7s %-6s %s\n' "$label" "${path:0:33}" "$expect" "$code" "$verdict"
}

# -------------------------------------------------------------------------
scenario_baseline() {
  hdr "BASELINE — legitimate traffic"
  raw_probe "homepage"              200 "/"
  raw_probe "healthz"               200 "/healthz"
  probe     "benign search"         200 "q=savings account"
  probe     "benign search, punctuation" 200 "q=O'Brien & Sons, Ltd."
}

# SQL injection payloads. Each targets a different detection technique,
# which is why six are sent rather than one:
#   tautology       a condition always true, to dump every row
#   union select    appends a second query to exfiltrate other tables
#   catalog probe   references a database-internal table to fingerprint it
#   stacked drop    terminates the statement and starts a destructive one
#   boolean blind   infers data from response timing, no output needed
#   comment evasion /**/ instead of spaces, to dodge naive pattern matching
#
# The `expect` argument lets the same payloads be reused for the WAF-off
# case: `./attack.sh sqli-open` expects 200, so "the attack succeeded" is
# a pass rather than a wall of failures.
scenario_sqli() {
  local expect="${1:-403}"
  hdr "SQL INJECTION — expecting $expect"
  probe "tautology"            "$expect" "q=' OR 1=1 --"
  probe "union select"         "$expect" "q=1 UNION SELECT NULL,user(),version()"
  probe "catalog probe"        "$expect" "q=abc pg_catalog xyz"
  probe "stacked drop"         "$expect" "q=1; DROP TABLE accounts--"
  probe "boolean blind"        "$expect" "q=1' AND SLEEP(5) AND 'a'='a"
  probe "comment evasion"      "$expect" "q=1/**/UNION/**/SELECT/**/password"
}

# Cross-site scripting payloads. XSS means getting the browser of a LATER
# visitor to execute your JavaScript, so each of these is a different way
# to smuggle a script past a filter: a plain tag, an event handler on a
# broken image, a javascript: URI, an SVG, a nested iframe, a body
# handler. Blocking only `<script>` catches almost none of them, which is
# the argument for a maintained rule set over hand-written patterns.
scenario_xss() {
  local expect="${1:-403}"
  hdr "CROSS-SITE SCRIPTING — expecting $expect"
  probe "script tag"           "$expect" "q=<script>alert(1)</script>"
  probe "img onerror"          "$expect" "q=<img src=x onerror=alert(1)>"
  probe "javascript URI"       "$expect" "q=javascript:alert(document.cookie)"
  probe "svg onload"           "$expect" "q=<svg/onload=alert(1)>"
  probe "iframe srcdoc"        "$expect" "q=<iframe srcdoc='<script>alert(1)</script>'>"
  probe "body onload"          "$expect" "q=<body onload=alert(1)>"
}

# ./attack.sh denylist
#
# Self-orchestrating: this scenario changes the policy itself rather than
# relying on you to have set it up first. It runs the full lifecycle, so
# a pass means the rule genuinely took effect AND genuinely reverted.
#
#   1. before    benign request succeeds
#   2. block     add your own IP to the denylist
#   3. during    the SAME benign request is now refused
#   4. evidence  the log attributes it to the denylist rule, not the WAF
#   5. after     remove the rule; the request succeeds again
#
# Step 4 matters more than it looks. A 403 on its own does not tell you
# WHICH rule produced it — the WAF, the geo rule and the denylist all
# return 403. Checking the logged priority is what distinguishes
# "my denylist works" from "something blocked this".
#
# Takes ~6 minutes, nearly all of it waiting for rule propagation.
scenario_denylist() {
  hdr "IP DENYLIST — full lifecycle against your own address"

  local ip; ip="$(my_public_ip 2>/dev/null)" || {
    warn "cannot detect your public IP; skipping"
    return
  }
  echo "  Testing by denylisting your own address: $ip"
  echo "  Layer 3/4 only — no request inspection, the IP alone decides."
  hr

  # --- 1. before ---
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${BASE}/" 2>/dev/null)"
  if [[ "$code" == "200" ]]; then
    PASS=$(( PASS + 1 )); printf '  1/5  before     benign request   %-5s ✓\n' "$code"
  else
    FAIL=$(( FAIL + 1 )); printf '  1/5  before     benign request   %-5s ✗ expected 200\n' "$code"
    printf '       Something is already blocking you. Try ./armor.sh reset\n'
    return
  fi

  # --- 2. block (armor.sh waits for propagation itself) ---
  printf '  2/5  blocking your IP...\n'
  "$HERE/armor.sh" deny-me 2>&1 | sed -n 's/^/       /p' | grep -E "live after|still getting" || true

  # --- 3. during ---
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${BASE}/" 2>/dev/null)"
  if [[ "$code" == "403" ]]; then
    PASS=$(( PASS + 1 )); printf '  3/5  blocked    benign request   %-5s ✓ BLOCKED\n' "$code"
  else
    FAIL=$(( FAIL + 1 )); printf '  3/5  blocked    benign request   %-5s ✗ expected 403\n' "$code"
  fi

  # --- 4. evidence: which rule actually did it? ---
  printf '  4/5  checking the log says it was the denylist rule...\n'
  sleep 45   # logs lag by up to a minute
  local prio
  prio="$(gcloud logging read \
      "resource.type=\"http_load_balancer\"
       jsonPayload.enforcedSecurityPolicy.name=\"${EDGE_POLICY}\"
       jsonPayload.statusDetails=\"denied_by_security_policy\"" \
      --limit=1 --freshness=5m \
      --format="value(jsonPayload.enforcedSecurityPolicy.priority)" 2>/dev/null \
      | tr -d '[:space:]')"
  if [[ "$prio" == "1000" ]]; then
    PASS=$(( PASS + 1 ))
    printf '       log shows priority 1000 (the denylist rule)   ✓\n'
  else
    FAIL=$(( FAIL + 1 ))
    printf '       log shows priority %s, expected 1000   ✗\n' "${prio:-<none>}"
    printf '       2000/2100 would mean the WAF blocked it, 1100 the geo rule.\n'
  fi

  # --- 5. after ---
  printf '  5/5  removing the block...\n'
  "$HERE/armor.sh" undeny-me 2>&1 | sed -n 's/^/       /p' | grep -E "live after|still getting" || true
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${BASE}/" 2>/dev/null)"
  if [[ "$code" == "200" ]]; then
    PASS=$(( PASS + 1 )); printf '       restored   benign request   %-5s ✓\n' "$code"
  else
    FAIL=$(( FAIL + 1 )); printf '       restored   benign request   %-5s ✗ expected 200\n' "$code"
  fi
}

# ./attack.sh geo
#
# Requires ./05-geo-probe.sh, which creates a VM in a US region.
#
# The point of two origins: blocking your own country and seeing a 403
# only proves the rule fires. It does not prove the rule is SELECTIVE —
# "deny everyone" would look identical. Sending the same request from a
# second country, and seeing it succeed, is what proves discrimination.
#
# Then the rule is flipped to block the OTHER country, and the results
# should swap. That symmetry is the real validation.
scenario_geo() {
  hdr "GEO BLOCKING — two origins, two countries"

  if ! probe_vm_ready; then
    warn "geo probe VM '$PROBE_VM' not found — skipping."
    warn "Create it with ./05-geo-probe.sh (a ~\$0.01/hour e2-micro in $PROBE_REGION)."
    warn "Without a second origin, a geo rule cannot be meaningfully validated."
    return
  fi

  local my_cc; my_cc="$(my_region_code 2>/dev/null)" || my_cc=""
  [[ -n "$my_cc" ]] || { warn "cannot detect your country; skipping"; return; }

  local probe_cc; probe_cc="$(gcloud compute ssh "$PROBE_VM" --zone="$PROBE_ZONE" \
    --tunnel-through-iap --quiet \
    --command="curl -fsS --max-time 10 https://ipinfo.io/country" 2>/dev/null | tr -d '[:space:]')"
  [[ -n "$probe_cc" ]] || probe_cc="US"

  if [[ "$my_cc" == "$probe_cc" ]]; then
    warn "both origins report $my_cc — cannot tell them apart. Pick a different PROBE_REGION."
    return
  fi

  echo "  your machine: $my_cc        probe VM: $probe_cc"
  echo "  Blocking one country at a time; the other must keep working."
  hr
  printf '  %-26s %-9s %-7s %-6s %s\n' "ORIGIN" "COUNTRY" "EXPECT" "GOT" ""

  # check_pair <blocked-country> — after blocking it, the blocked origin
  # should 403 and the other should still get 200.
  local here_code probe_code
  _check_pair() {
    local blocked="$1" here_expect probe_expect
    if [[ "$blocked" == "$my_cc" ]]; then here_expect=403; probe_expect=200
    else                                   here_expect=200; probe_expect=403; fi

    here_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${BASE}/" 2>/dev/null)"

    # armor.sh only waits for the rule to be live as seen from THIS
    # machine. The probe sits at a different Google edge location, which
    # may receive the update a little later, so poll rather than taking a
    # single sample and declaring a failure that is really just timing.
    local tries
    for (( tries = 0; tries < 12; tries++ )); do
      probe_code="$(probe_from_vm /)"
      [[ "$probe_code" == "$probe_expect" ]] && break
      sleep 10
    done

    local v
    if [[ "$here_code" == "$here_expect" ]]; then
      PASS=$(( PASS + 1 )); v="✓"; [[ "$here_code" == "403" ]] && v="✓ BLOCKED"
    else FAIL=$(( FAIL + 1 )); v="✗ expected $here_expect"; fi
    printf '  %-26s %-9s %-7s %-6s %s\n' "your machine" "$my_cc" "$here_expect" "$here_code" "$v"

    if [[ "$probe_code" == "$probe_expect" ]]; then
      PASS=$(( PASS + 1 )); v="✓"; [[ "$probe_code" == "403" ]] && v="✓ BLOCKED"
    else FAIL=$(( FAIL + 1 )); v="✗ expected $probe_expect"; fi
    printf '  %-26s %-9s %-7s %-6s %s\n' "probe VM ($PROBE_REGION)" "$probe_cc" "$probe_expect" "$probe_code" "$v"
  }

  # --- Round 1: block your own country ---
  echo
  printf '  --- blocking %s ---\n' "$my_cc"
  "$HERE/armor.sh" geo "$my_cc" 2>&1 | grep -E "live after|still getting" | sed 's/^/       /' || true
  _check_pair "$my_cc"

  # --- Round 2: block the probe's country instead ---
  echo
  printf '  --- blocking %s instead ---\n' "$probe_cc"
  "$HERE/armor.sh" geo "$probe_cc" 2>&1 | grep -E "live after|still getting" | sed 's/^/       /' || true
  _check_pair "$probe_cc"

  # --- Clean up ---
  echo
  printf '  --- removing the geo rule ---\n'
  "$HERE/armor.sh" geo off 2>&1 | grep -E "live after|still getting" | sed 's/^/       /' || true
}

# Sends requests as fast as a loop allows, to trip the app-tier rate limit.
#
# Note where this is enforced: not at the edge, but at the internal load
# balancer, past the Private Service Connect hop. So a 429 here also
# proves the whole PSC path is working.
#
# The limit is per backend service, not global, and the burst has to
# out-pace the threshold to trigger — sending 40 requests slowly over
# several minutes would never trip a 10-per-60-seconds rule.
scenario_flood() {
  local n="${1:-40}"
  hdr "RATE LIMIT — burst of $n requests to $BAN_PATH"
  echo "  Enforced by the app-tier policy at the internal ALB, past the PSC hop."
  echo "  Threshold: ${BAN_COUNT} requests / ${BAN_INTERVAL}s, then ban for ${BAN_DURATION}s."
  hr

  local i code n200=0 n429=0 first429=""
  for (( i = 1; i <= n; i++ )); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${BASE}${BAN_PATH}" 2>/dev/null)"
    case "$code" in
      429) n429=$(( n429 + 1 )); [[ -z "$first429" ]] && first429="$i" ;;
      *)   n200=$(( n200 + 1 )) ;;
    esac
    # Redraw in place on a terminal; on a pipe that would produce one
    # unreadable line, so only print at the end there.
    if [[ -t 1 ]]; then
      printf '\r  sent %3d/%d   allowed %3d   throttled %3d' "$i" "$n" "$n200" "$n429"
    fi
  done
  [[ -t 1 ]] || printf '  sent %3d/%d   allowed %3d   throttled %3d' "$n" "$n" "$n200" "$n429"
  echo; hr

  if (( n429 == 0 )); then
    FAIL=$(( FAIL + 1 ))
    printf '  ✗ no 429 seen. Is the rule on? ./armor.sh ratelimit on\n'
    printf '    Note: thresholds are per backend service, and the burst must\n'
    printf '    outpace %s requests per %ss to trip.\n' "$BAN_COUNT" "$BAN_INTERVAL"
    printf '    Rule changes also take 1-3 min to propagate — if you just ran\n'
    printf '    `armor.sh ratelimit on`, wait and try again.\n'
    return
  fi

  PASS=$(( PASS + 1 ))
  printf '  ✓ THROTTLED — first 429 at request %s (%d of %d rejected)\n' "$first429" "$n429" "$n"

  # Checking merely that *a* 429 appeared is a weak assertion — it would
  # pass even if the limit were wildly misconfigured. Compare where the
  # first rejection actually landed against the configured threshold.
  # Allow generous slack: the counter is per backend service and the
  # window slides, so an exact match is not expected.
  local lo=$(( BAN_COUNT / 2 ))
  local hi=$(( BAN_COUNT * 3 ))
  if (( first429 < lo || first429 > hi )); then
    printf '  ! threshold looks off: expected the first 429 near request %s\n' "$BAN_COUNT"
    printf '    (config: BAN_COUNT=%s per BAN_INTERVAL=%ss), got it at %s.\n' \
           "$BAN_COUNT" "$BAN_INTERVAL" "$first429"
  else
    printf '    consistent with BAN_COUNT=%s per %ss\n' "$BAN_COUNT" "$BAN_INTERVAL"
  fi

  printf '    Confirm WHICH rule fired with: ./logs.sh --app\n'
  printf '    configuredAction should read RATE_BASED_BAN, not THROTTLE —\n'
  printf '    if it says THROTTLE, the catch-all rule is shadowing the ban.\n'
}

# ./attack.sh ban
#
# Proves the difference between `throttle` and `rate-based-ban`, which the
# flood scenario alone cannot show: both produce 429s.
#
# The distinction is what happens AFTER the client stops. A throttle
# forgives you as soon as the rate window slides past. A ban keeps
# rejecting you for ban-duration-sec regardless.
#
# So: trip the limit, go quiet for longer than the threshold interval but
# less than the ban duration, then send one request. Still 429 means a
# real ban. A 200 means it was only ever throttling.
#
# Takes BAN_INTERVAL + ~15s, so it is deliberately not part of `all`.
scenario_ban() {
  hdr "RATE-BASED BAN — does the block persist after traffic stops?"
  echo "  Tripping the ban on $BAN_PATH, then going quiet to see if it holds."
  hr

  local i code n429=0
  for (( i = 1; i <= BAN_COUNT * 3; i++ )); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${BASE}${BAN_PATH}" 2>/dev/null)"
    [[ "$code" == "429" ]] && n429=$(( n429 + 1 ))
  done

  if (( n429 == 0 )); then
    FAIL=$(( FAIL + 1 ))
    printf '  ✗ never got throttled, so there is no ban to test.\n'
    printf '    Run ./armor.sh ratelimit on and wait 1-3 min.\n'
    return
  fi
  printf '  tripped: %d rejections during the burst\n' "$n429"

  # Wait past the rate-limit window, but well inside the ban duration.
  local quiet=$(( BAN_INTERVAL + 15 ))
  printf '  going quiet for %ss (threshold window is %ss, ban lasts %ss)' \
         "$quiet" "$BAN_INTERVAL" "$BAN_DURATION"
  for (( i = 0; i < quiet; i += 5 )); do printf '.'; sleep 5; done
  echo

  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${BASE}${BAN_PATH}" 2>/dev/null)"
  hr
  if [[ "$code" == "429" ]]; then
    PASS=$(( PASS + 1 ))
    printf '  ✓ STILL BANNED after %ss of silence (HTTP %s)\n' "$quiet" "$code"
    printf '    This is rate-based-ban, not throttle: the block outlives the traffic.\n'
  else
    FAIL=$(( FAIL + 1 ))
    printf '  ✗ got HTTP %s — the block lifted once the rate window passed.\n' "$code"
    printf '    That is throttle behaviour. Check ./armor.sh status: is the\n'
    printf '    rate-based-ban rule above the catch-all throttle rule?\n'
  fi
}

# -------------------------------------------------------------------------
# ---- Argument handling ---------------------------------------------------
# "$@" is every argument. Default to "all" when none were given, so bare
# `./attack.sh` does something useful.
scenarios=("$@")
[[ ${#scenarios[@]} -eq 0 ]] && scenarios=("all")
RAN_ALL=0

echo
echo "Target: $BASE"

for s in "${scenarios[@]}"; do
  case "$s" in
    baseline) scenario_baseline ;;
    sqli)     scenario_sqli ;;
    xss)      scenario_xss ;;
    # When the WAF is off, the attacks are supposed to succeed. These variants
    # make that an explicit, passing expectation rather than a wall of ✗.
    sqli-open) scenario_sqli 200 ;;
    xss-open)  scenario_xss 200 ;;
    denylist) scenario_denylist ;;
    geo)      scenario_geo ;;
    flood)    scenario_flood ;;
    ban)      scenario_ban ;;
    # `all` deliberately EXCLUDES flood and ban. Both leave you rate
    # limited or banned for a couple of minutes, so running them here
    # would make every following scenario fail for the wrong reason.
    # The note printed at the end says so, rather than leaving you to
    # assume rate limiting was covered.
    all)      scenario_baseline; scenario_sqli; scenario_xss; RAN_ALL=1 ;;
    *)        echo "unknown scenario: $s" >&2
              echo "choose from: baseline sqli xss sqli-open xss-open denylist geo flood ban all" >&2
              exit 1 ;;
  esac
done

echo
hr
printf '  %d matched expectations, %d did not\n' "$PASS" "$FAIL"
hr

# Say plainly what `all` did not cover, so nobody concludes rate limiting
# passed when it was never exercised.
if (( RAN_ALL )); then
  echo "  Not covered by 'all': rate limiting. Those scenarios leave you"
  echo "  throttled or banned for a few minutes, so they are opt-in:"
  echo "      ./attack.sh flood    trip the limit"
  echo "      ./attack.sh ban      prove the ban outlives the traffic"
  echo
fi

echo "  See what Cloud Armor logged:  ./logs.sh        (edge policy)"
echo "                                ./logs.sh --app  (rate limiting)"
echo

# The last command in a script determines its exit status. This test
# yields 0 when nothing failed and 1 otherwise, so the script can be used
# in a CI pipeline to catch a policy regression.
[[ "$FAIL" -eq 0 ]]
