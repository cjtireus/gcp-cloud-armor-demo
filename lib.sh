#!/usr/bin/env bash
# =========================================================================
# Shared helpers, sourced by every other script in this repo.
#
# This file defines no commands of its own. Each script starts with
#
#     source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
#
# which runs this file inside the calling shell, so every variable and
# function below becomes available to it. That is why you will not see any
# repeated configuration loading or helper definitions elsewhere.
# =========================================================================

# ${BASH_SOURCE[0]} is the path of THIS file, which is not necessarily the
# directory you ran the script from. Resolving it means the scripts work
# whether you run `./00-network.sh` or `/some/long/path/00-network.sh`.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# "${VAR:-default}" means "use $VAR if it is set and non-empty, otherwise
# use the default". So you can point at an alternative config with
#     CONFIG=/path/to/other.env ./00-network.sh
CONFIG="${CONFIG:-$HERE/config.env}"

# `[[ -f FILE ]]` tests that FILE exists and is a regular file. The `||`
# runs the block only if that test fails. `>&2` sends output to stderr,
# which is the convention for errors so they are not captured by a pipe.
[[ -f "$CONFIG" ]] || {
  echo "config not found: $CONFIG" >&2
  echo "Run: cp config.env.example config.env && \$EDITOR config.env" >&2
  exit 1
}
# `source` executes config.env in this shell, so its `export VAR=...` lines
# become real variables here.
# shellcheck disable=SC1090   # the path is dynamic; shellcheck cannot follow it
source "$CONFIG"

# The `: "${VAR:?message}"` idiom is a guard clause. `:` is a no-op builtin,
# and `${VAR:?msg}` aborts the script with `msg` if VAR is unset or empty.
# Failing here, with a clear message, beats failing twenty gcloud calls later.
: "${PROJECT_ID:?PROJECT_ID must be set in config.env}"
: "${REGION:?REGION must be set in config.env}"
: "${PREFIX:?PREFIX must be set in config.env}"

# Tell gcloud which project to use via an environment variable rather than
# `gcloud config set project`. Config is global state shared by every gcloud
# process on this machine; an env var only affects commands this script runs.
# That means the demo cannot silently repoint your shell at another project.
export CLOUDSDK_CORE_PROJECT="$PROJECT_ID"

# ---- Output helpers ------------------------------------------------------
# "$*" joins all arguments into one string. These exist purely so progress
# output looks consistent across eleven scripts.
say()  { echo -e "\n######## $* ########"; }   # section heading
ok()   { echo "  ✓ $*"; }                      # something succeeded
warn() { echo "  ! $*" >&2; }                  # notable, but not fatal
die()  { echo -e "\nERROR: $*" >&2; exit 1; }  # fatal: print and stop

# ---- Derived resource names ---------------------------------------------
# Every resource name is built from $PREFIX so the whole demo can be renamed
# from one line in config.env, and so teardown can find everything it made.
CONSUMER_SUBNET="${PREFIX}-consumer-subnet"
GKE_SUBNET="${PREFIX}-gke-subnet"
PROXY_SUBNET="${PREFIX}-proxy-subnet"
PSC_NAT_SUBNET="${PREFIX}-psc-nat-subnet"

# A Google Cloud HTTP load balancer is not one object. It is a chain of five,
# each pointing at the next, and you create them in this order:
#
#   forwarding rule  ← the IP and port clients actually connect to
#        │
#   target proxy     ← terminates HTTP and decides where to look next
#        │
#   URL map          ← routes by host/path to a backend service
#        │
#   backend service  ← the pool, health checks, and the Cloud Armor policy
#        │
#   NEG / instance group  ← the actual endpoints serving traffic
#
# Teardown deletes them in exactly the reverse order, because each one pins
# the next and Google Cloud refuses to delete a resource still in use.
EDGE_IP_NAME="${PREFIX}-edge-ip"
EDGE_BACKEND="${PREFIX}-edge-backend"
EDGE_URL_MAP="${PREFIX}-edge-url-map"
EDGE_PROXY="${PREFIX}-edge-http-proxy"
EDGE_FWD_RULE="${PREFIX}-edge-fwd-rule"

# The two halves of the Private Service Connect link:
#   SERVICE_ATTACHMENT  producer side — "here is a service I publish"
#   PSC_NEG             consumer side — "I want to consume that service"
PSC_NEG="${PREFIX}-psc-neg"
SERVICE_ATTACHMENT="${PREFIX}-app-attachment"

# The optional geo probe: a test client in another country.
PROBE_SUBNET="${PREFIX}-probe-subnet"

# ---- Idempotency helpers -------------------------------------------------
# "Idempotent" means running it twice does the same thing as running it once.
# Every script here can be re-run safely after a failure, which matters when
# a 30-minute build dies at minute 25.
#
# The trick: `gcloud ... describe` exits 0 if the resource exists and non-zero
# if it does not. `&>/dev/null` discards both stdout and stderr so we only
# care about that exit code. Used as:
#
#     exists_network "$VPC" || gcloud compute networks create "$VPC" ...
#
# Note which commands need a scope flag. Some resources are global (one per
# project), some regional (one per region) — and gcloud needs to be told which
# it is looking for.
exists_network()    { gcloud compute networks describe "$1" &>/dev/null; }
exists_subnet()     { gcloud compute networks subnets describe "$1" --region="$REGION" &>/dev/null; }
exists_firewall()   { gcloud compute firewall-rules describe "$1" &>/dev/null; }
exists_address()    { gcloud compute addresses describe "$1" --global &>/dev/null; }
exists_cluster()    { gcloud container clusters describe "$CLUSTER_NAME" --location="$REGION" &>/dev/null; }
exists_neg()        { gcloud compute network-endpoint-groups describe "$1" --region="$REGION" &>/dev/null; }
exists_attachment() { gcloud compute service-attachments describe "$1" --region="$REGION" &>/dev/null; }
exists_backend()    { gcloud compute backend-services describe "$1" --global &>/dev/null; }
exists_url_map()    { gcloud compute url-maps describe "$1" --global &>/dev/null; }
exists_proxy()      { gcloud compute target-http-proxies describe "$1" --global &>/dev/null; }
exists_fwd_rule()   { gcloud compute forwarding-rules describe "$1" --global &>/dev/null; }
# A VM is zonal, not regional — note the different scope flag again.
exists_instance()   { gcloud compute instances describe "$1" --zone="${PROBE_ZONE}" &>/dev/null; }
exists_probe_subnet() { gcloud compute networks subnets describe "$1" --region="${PROBE_REGION}" &>/dev/null; }

# Security policies come in both flavours, so this one takes the scope as an
# optional second argument:
#     exists_policy armor-edge              → global policy
#     exists_policy armor-app europe-west1  → regional policy
# "${2:-}" is "$2 or empty string", which avoids an unbound-variable error
# when the caller passes only one argument.
exists_policy() {
  if [[ -n "${2:-}" ]]; then
    gcloud compute security-policies describe "$1" --region="$2" &>/dev/null
  else
    gcloud compute security-policies describe "$1" --global &>/dev/null
  fi
}

# ---- Who am I on the internet? -------------------------------------------
# Several demo steps block or allow *your own* address, so the scripts need
# to know your public IP. Your machine cannot know this by itself — behind
# NAT, your local interface has a private address like 192.168.x.x — so we
# ask an external service what address it sees the request coming from.
#
# The result is cached in a variable because a single script may need it
# several times and there is no reason to make the same HTTP call repeatedly.
# A leading underscore is a convention meaning "internal, do not use directly".
_MY_IP=""
my_public_ip() {
  if [[ -z "$_MY_IP" ]]; then
    # curl flags: -f fail on HTTP errors, -s silent, -S still show errors.
    # `tr -d '[:space:]'` strips the trailing newline these services return.
    # The `||` chain falls back to a second provider if the first is down.
    _MY_IP="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')" \
      || _MY_IP="$(curl -fsS --max-time 10 https://ifconfig.me 2>/dev/null | tr -d '[:space:]')" \
      || _MY_IP=""
  fi
  # Return non-zero (failure) rather than echoing nothing, so callers can
  # detect the failure with `|| die "..."` instead of silently using "".
  [[ -n "$_MY_IP" ]] || return 1
  echo "$_MY_IP"
}

# Same idea for the country code, used by the geo-blocking demo so it can
# block your own country and you can see the effect immediately.
_MY_CC=""
my_region_code() {
  if [[ -z "$_MY_CC" ]]; then
    _MY_CC="$(curl -fsS --max-time 10 https://ipinfo.io/country 2>/dev/null | tr -d '[:space:]')" || _MY_CC=""
  fi
  [[ -n "$_MY_CC" ]] || return 1
  echo "$_MY_CC"
}

# ---- Edge load balancer address -----------------------------------------
# `--format="value(address)"` makes gcloud print just that one field with no
# header or quoting, which is what you want when assigning to a variable.
# Compare with the default output, which is a human-readable table.
edge_ip() {
  gcloud compute addresses describe "$EDGE_IP_NAME" --global \
    --format="value(address)" 2>/dev/null
}

# Same thing, but fails loudly with a hint instead of returning empty. Use
# this in scripts that cannot do anything useful without the address.
require_edge_ip() {
  local ip
  ip="$(edge_ip)" || true
  [[ -n "$ip" ]] || die "Edge IP '$EDGE_IP_NAME' not found. Run ./00-network.sh first."
  echo "$ip"
}

# ---- kubectl -------------------------------------------------------------
# kubectl reads cluster credentials from the file named by $KUBECONFIG,
# defaulting to ~/.kube/config. Pointing it at a file inside this repo means
# `gcloud container clusters get-credentials` cannot overwrite or switch the
# context of whatever cluster you were already working with. The file is
# listed in .gitignore because it contains an access token.
export KUBECONFIG="${KUBECONFIG_OVERRIDE:-$HERE/.kube-config}"

# Fetch credentials only if we do not already have working ones. The
# `kubectl cluster-info` call is the actual test — the file existing is not
# enough, since its token expires.
kube_creds() {
  exists_cluster || die "Cluster '$CLUSTER_NAME' not found. Run ./01-gke.sh first."
  if [[ ! -f "$KUBECONFIG" ]] || ! kubectl cluster-info &>/dev/null; then
    gcloud container clusters get-credentials "$CLUSTER_NAME" \
      --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1 \
      || die "Could not fetch cluster credentials for '$CLUSTER_NAME'."
  fi
}

# ---- Waiting for a Cloud Armor rule to actually take effect --------------
# This is the single most important thing to understand about operating
# Cloud Armor, and it surprises almost everyone the first time.
#
# When `gcloud compute security-policies rules create` returns successfully,
# the rule exists in the API. It is NOT yet enforcing. A global policy has to
# be pushed out to Google's edge points of presence worldwide, and that takes
# time — measured on this demo, anywhere from 15 seconds to over 3 minutes.
# Worse, two rules created back to back do not necessarily go live together.
#
# So if you create a WAF rule and immediately send an attack, you will get a
# 200 and conclude the WAF is broken. It is not; you were just early.
#
# Rather than guessing with `sleep 120`, this function sends a real request
# and waits until the response proves the new rule is live.
#
#   await_edge <expected-http-code> [extra curl args...]
#
# e.g. await_edge 403 --get --data-urlencode "q=' OR 1=1 --"
#      "keep probing with this SQL injection until it starts being blocked"
await_edge() {
  local expect="$1"; shift   # `shift` drops $1 so "$@" is just the curl args
  local eip i code

  eip="$(edge_ip 2>/dev/null)" || return 0
  [[ -n "$eip" ]] || return 0
  # If the edge load balancer does not exist yet there is nothing to probe.
  # This happens during `armor.sh create`, which runs before 04-edge.sh.
  exists_fwd_rule "$EDGE_FWD_RULE" || return 0

  # Why three consecutive matches rather than one: the rollout reaches edge
  # locations at different times, and your requests may not all land on the
  # same one. A single matching response can arrive while other edges still
  # have the old rule, so the very next request disagrees. Requiring a streak
  # makes a false "it's ready" much less likely.
  local streak=0
  printf "  waiting for the rule to take effect (typically 1-3 min) "
  for i in $(seq 1 90); do   # 90 attempts × 5s = 450s ceiling
    # -o /dev/null throws away the body; -w '%{http_code}' prints just the
    # status code, which is all we need to decide whether the rule is live.
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" "http://${eip}/" 2>/dev/null)"
    if [[ "$code" == "$expect" ]]; then
      streak=$(( streak + 1 ))
      if (( streak >= 3 )); then
        printf " live after %ss\n" "$(( i * 5 ))"
        return 0
      fi
    else
      streak=0   # any disagreement resets the count
    fi
    printf "."    # a progress dot, so a 3-minute wait does not look hung
    sleep 5
  done
  printf " still getting %s after 450s\n" "$code"
  warn "the rule may need longer, or something else is matching first — check ./armor.sh status"
  return 1
}

# Probe payloads used by await_edge to detect whether each WAF rule is live.
# There are two because the SQLi and XSS rules propagate independently —
# observed here, SQLi went live about a minute before XSS. Waiting on only
# one of them means attack.sh reports half the suite failing.
#
# These are bash arrays. "${WAF_CANARY[@]}" expands to the elements as
# separate arguments, which keeps the payload intact even though it contains
# spaces and quotes. A plain string would be word-split and mangled.
WAF_CANARY=(--get --data-urlencode "q=' OR 1=1 --")
XSS_CANARY=(--get --data-urlencode "q=<script>alert(1)</script>")

# ---- The geo probe VM ----------------------------------------------------
# Runs a curl on the probe VM and prints the HTTP status code it saw.
# Because the VM is in another country, its requests carry a different
# origin.region_code, which is the only way to prove a geo rule is
# selective rather than blocking everyone.
#
# SSH through IAP rather than over the public internet: the VM has an
# external IP so its OUTBOUND traffic has a US address, but inbound SSH is
# firewalled to Google's IAP range only. --quiet stops gcloud prompting to
# generate an SSH key on first use, which would hang a script.
probe_from_vm() {
  local path="${1:-/}"
  local eip; eip="$(edge_ip 2>/dev/null)"
  [[ -n "$eip" ]] || { echo "000"; return 1; }

  gcloud compute ssh "$PROBE_VM" \
    --zone="$PROBE_ZONE" --tunnel-through-iap --quiet \
    --command="curl -s -o /dev/null -w '%{http_code}' --max-time 20 'http://${eip}${path}'" \
    2>/dev/null | tr -d '[:space:]'
}

# Is the probe VM available? Scenarios that need it skip with a clear
# message rather than failing when it was never created.
probe_vm_ready() {
  [[ -n "${PROBE_VM:-}" ]] || return 1
  exists_instance "$PROBE_VM"
}

# ---- Generic polling -----------------------------------------------------
# Same idea as await_edge, but for "does this resource exist / is it ready"
# rather than "does the edge behave differently". Used while waiting on the
# GKE cluster and the load balancers, which take minutes to provision.
#
#   wait_for <timeout-seconds> <description> <command...>
#
# "$@" after the two shifts is the command to run; it is executed directly,
# so you can pass either a real command or the name of a shell function.
wait_for() {
  local timeout="$1"; shift
  local desc="$1"; shift
  local waited=0 interval=10

  printf "  waiting for %s " "$desc"
  while (( waited < timeout )); do
    if "$@" &>/dev/null; then
      printf " ready (%ds)\n" "$waited"
      return 0
    fi
    printf "."
    sleep "$interval"
    waited=$(( waited + interval ))
  done
  printf " TIMEOUT after %ds\n" "$timeout"
  return 1
}
