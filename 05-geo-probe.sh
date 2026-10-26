#!/usr/bin/env bash
# =========================================================================
# 05 — The geo probe VM.  (OPTIONAL — only ./attack.sh geo needs it)
#
# WHY THIS EXISTS
# A geo-blocking rule can only be validated with traffic from two
# different countries. Blocking your own country and confirming you get a
# 403 proves the rule fires, but it does not prove the rule DISCRIMINATES
# — a "deny everyone" rule would pass that test identically. You need a
# request from somewhere else that still succeeds.
#
# WHY NOT A PUBLIC PROXY
# Free open proxies are unreliable, usually short-lived, and frequently
# operated by people who read and modify the traffic passing through them.
# Routing test traffic through an untrusted intermediary is a poor idea
# generally and a worse one in a demo about security. A VM you own, in a
# region you chose, costs about a cent an hour and answers the question
# without trusting anybody.
#
# WHAT IT BUILDS
# Its own small VPC in a US region, plus one e2-micro. The VM is
# deliberately NOT in the consumer or producer VPC: it represents a client
# out on the internet, not part of the protected architecture.
#
# The VM has an external IP so its outbound requests carry a US address.
# Inbound SSH is restricted to Google's Identity-Aware Proxy range, so
# port 22 is not exposed to the internet.
#
# Takes about a minute.
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# =========================================================================
say "Probe VPC — $PROBE_VPC ($PROBE_REGION)"
# =========================================================================
if exists_network "$PROBE_VPC"; then
  ok "$PROBE_VPC already exists"
else
  gcloud compute networks create "$PROBE_VPC" --subnet-mode=custom >/dev/null \
    || die "failed to create $PROBE_VPC"
  ok "created $PROBE_VPC"
fi

# Note --region=$PROBE_REGION here, not $REGION. This is the one piece of
# the demo that lives outside europe-west1, and that is the entire point.
if exists_probe_subnet "$PROBE_SUBNET"; then
  ok "$PROBE_SUBNET already exists"
else
  gcloud compute networks subnets create "$PROBE_SUBNET" \
    --network="$PROBE_VPC" \
    --region="$PROBE_REGION" \
    --range="$PROBE_SUBNET_RANGE" >/dev/null \
    || die "failed to create $PROBE_SUBNET"
  ok "created $PROBE_SUBNET ($PROBE_SUBNET_RANGE in $PROBE_REGION)"
fi

# =========================================================================
say "Firewall — SSH via Identity-Aware Proxy only"
# =========================================================================
# 35.235.240.0/20 is Google's IAP TCP forwarding range. Allowing SSH from
# only this range means port 22 is unreachable from the internet even
# though the VM has a public address; connections must come through IAP,
# which enforces IAM. This is the standard pattern for administering VMs
# without exposing SSH, and it is worth using by default.
FW_IAP="${PREFIX}-probe-allow-iap-ssh"
if exists_firewall "$FW_IAP"; then
  ok "$FW_IAP already exists"
else
  gcloud compute firewall-rules create "$FW_IAP" \
    --network="$PROBE_VPC" \
    --direction=INGRESS \
    --action=allow \
    --rules=tcp:22 \
    --source-ranges=35.235.240.0/20 \
    --description="SSH to the geo probe via IAP only" >/dev/null \
    || die "failed to create $FW_IAP"
  ok "created $FW_IAP"
fi

# =========================================================================
say "Probe VM — $PROBE_VM"
# =========================================================================
if exists_instance "$PROBE_VM"; then
  ok "$PROBE_VM already exists"
else
  # e2-micro is the smallest general-purpose machine type. The image is
  # Debian 12, which ships curl.
  #
  # No --no-address flag, so the VM gets an ephemeral external IP. That is
  # required here: without a public address its traffic could not reach
  # the edge load balancer from a US source, which is the whole purpose.
  gcloud compute instances create "$PROBE_VM" \
    --zone="$PROBE_ZONE" \
    --machine-type="$PROBE_MACHINE" \
    --subnet="$PROBE_SUBNET" \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --boot-disk-size=10GB \
    --scopes=cloud-platform \
    --labels=purpose=cloud-armor-geo-probe >/dev/null \
    || die "failed to create $PROBE_VM"
  ok "created $PROBE_VM ($PROBE_MACHINE in $PROBE_ZONE)"
fi

PROBE_IP="$(gcloud compute instances describe "$PROBE_VM" --zone="$PROBE_ZONE" \
  --format="value(networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null)"
ok "probe public IP: ${PROBE_IP:-unknown}"

# =========================================================================
say "Waiting for SSH"
# =========================================================================
# A VM reports RUNNING before its guest OS has finished booting and
# started sshd, so the first few connection attempts normally fail. Poll
# rather than sleeping a fixed amount.
probe_ssh_ready() {
  gcloud compute ssh "$PROBE_VM" --zone="$PROBE_ZONE" \
    --tunnel-through-iap --quiet --command="true" &>/dev/null
}
wait_for 300 "SSH on $PROBE_VM" probe_ssh_ready \
  || die "could not SSH to $PROBE_VM. Is the IAP API enabled, and do you have
     roles/iap.tunnelResourceAccessor? Try manually:
       gcloud compute ssh $PROBE_VM --zone=$PROBE_ZONE --tunnel-through-iap"

# =========================================================================
say "Confirming the probe looks like a different country"
# =========================================================================
# Cloud Armor derives origin.region_code from the source IP using Google's
# own geolocation database. This check uses a third-party lookup, so it is
# indicative rather than authoritative — but if it disagrees with your own
# country, the geo test will work.
PROBE_CC="$(gcloud compute ssh "$PROBE_VM" --zone="$PROBE_ZONE" \
  --tunnel-through-iap --quiet \
  --command="curl -fsS --max-time 10 https://ipinfo.io/country 2>/dev/null" 2>/dev/null \
  | tr -d '[:space:]')"
MY_CC="$(my_region_code 2>/dev/null)" || MY_CC="unknown"

echo
printf "  your machine : %s (%s)\n" "$(my_public_ip 2>/dev/null || echo '?')" "$MY_CC"
printf "  probe VM     : %s (%s)\n" "${PROBE_IP:-?}" "${PROBE_CC:-?}"
echo

if [[ -n "$PROBE_CC" && "$PROBE_CC" == "$MY_CC" ]]; then
  warn "Both origins report the same country ($MY_CC)."
  warn "The geo test cannot distinguish them. Pick a PROBE_REGION further away."
elif [[ -z "$PROBE_CC" ]]; then
  warn "Could not determine the probe's country; the geo test may still work."
else
  ok "two distinct origins: $MY_CC and $PROBE_CC"
fi

echo
echo "Now run:  ./attack.sh geo"
