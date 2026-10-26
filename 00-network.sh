#!/usr/bin/env bash
# =========================================================================
# 00 — Networks.
#
# Builds the two VPC networks everything else sits in, plus the firewall
# rules and the public IP address the demo will be reachable on.
#
# WHY TWO VPCs
# A VPC network in Google Cloud is an isolated private network. By default
# two VPCs cannot talk to each other at all — no routes, no connectivity.
# That isolation is the point here:
#
#   armor-producer-vpc   GKE and the internal load balancer live here. It is
#                        never reachable from the internet, and never
#                        reachable from the consumer VPC by normal routing.
#
#   armor-consumer-vpc   The edge load balancer's connection into the
#                        producer's published service lives here.
#
# They are joined by exactly one thing: a Private Service Connect link,
# built in 03 and 04. PSC exposes a single *service* across the boundary
# rather than making the networks routable to each other. That is the
# difference between "these two networks are connected" and "this one
# service is published to that network".
#
# WHY THE SUBNETS HAVE DIFFERENT PURPOSES
# Most subnets just hold VMs. Two of the ones below are special-purpose
# subnets that Google Cloud reserves for its own managed infrastructure;
# you cannot put your own resources in them. See the comments inline.
# =========================================================================

# `set -u`  : treat use of an unset variable as an error, instead of
#             silently substituting an empty string (which can turn
#             `rm -rf "$DIR/"` into something catastrophic).
# `-o pipefail` : a pipeline fails if ANY command in it fails, not just the
#             last one. Without it, `false | tee log` reports success.
#
# Deliberately NOT using `set -e` (exit on any error): these scripts check
# exit codes explicitly and want to carry on past expected failures, such as
# "this resource already exists".
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# =========================================================================
say "Enabling APIs"
# =========================================================================
# Google Cloud APIs are off by default in a new project. Calling a disabled
# API returns a confusing permission-style error rather than "this is
# turned off", so enable them up front. Enabling is idempotent — asking for
# an already-enabled API is a no-op, which is why this can run every time.
apis=(
  "compute.googleapis.com"          # VPCs, subnets, load balancers, Cloud Armor
  "container.googleapis.com"        # GKE
  "networksecurity.googleapis.com"  # security policy resources
  "logging.googleapis.com"          # where Cloud Armor decisions are recorded
  "monitoring.googleapis.com"       # metrics
)
for api in "${apis[@]}"; do
  # The grep filters gcloud's verbose output down to one useful line.
  # `|| true` stops a non-matching grep (exit 1) from looking like a failure.
  gcloud services enable "$api" 2>&1 | grep -Ei "Enabled|already" || true
done
ok "APIs enabled"

# =========================================================================
say "Consumer VPC — $CONSUMER_VPC"
# =========================================================================
# `--subnet-mode=custom` means "do not auto-create a subnet in every region".
# The alternative, `auto`, creates one subnet in all ~40 regions with
# predefined ranges. Custom mode is standard practice for anything real: you
# decide which regions exist and which IP ranges they use.
if exists_network "$CONSUMER_VPC"; then
  ok "$CONSUMER_VPC already exists"
else
  gcloud compute networks create "$CONSUMER_VPC" --subnet-mode=custom >/dev/null \
    || die "failed to create $CONSUMER_VPC"
  ok "created $CONSUMER_VPC"
fi

if exists_subnet "$CONSUMER_SUBNET"; then
  ok "$CONSUMER_SUBNET already exists"
else
  # This subnet exists to hold one thing: the Private Service Connect NEG
  # created in 04. That NEG consumes a single /32 address from this range,
  # which the edge load balancer uses as its source when talking to the
  # producer's published service. A /24 is far more than needed, but small
  # subnets are a false economy — you cannot resize one later without
  # recreating it.
  gcloud compute networks subnets create "$CONSUMER_SUBNET" \
    --network="$CONSUMER_VPC" \
    --region="$REGION" \
    --range="$CONSUMER_SUBNET_RANGE" >/dev/null \
    || die "failed to create $CONSUMER_SUBNET"
  ok "created $CONSUMER_SUBNET ($CONSUMER_SUBNET_RANGE)"
fi

# =========================================================================
say "Producer VPC — $PRODUCER_VPC"
# =========================================================================
if exists_network "$PRODUCER_VPC"; then
  ok "$PRODUCER_VPC already exists"
else
  gcloud compute networks create "$PRODUCER_VPC" --subnet-mode=custom >/dev/null \
    || die "failed to create $PRODUCER_VPC"
  ok "created $PRODUCER_VPC"
fi

# --- Subnet 1 of 3: the GKE nodes ---
#
# A GKE cluster needs three separate IP ranges, because nodes, pods and
# services are all individually addressable:
#
#   primary range    one address per NODE (the VMs)
#   secondary "pods" one address per POD — this is why it is by far the
#                    largest; a cluster can run thousands of pods
#   secondary "svcs" one address per Kubernetes Service (ClusterIP)
#
# "Secondary ranges" are additional CIDRs attached to the same subnet, an
# arrangement specific to this alias-IP model. Specifying them explicitly
# rather than letting GKE pick means you know exactly what is allocated, and
# teardown can clean up predictably.
if exists_subnet "$GKE_SUBNET"; then
  ok "$GKE_SUBNET already exists"
else
  # `--enable-private-ip-google-access` lets VMs with no external IP reach
  # Google APIs (Artifact Registry, Logging, and so on) over internal
  # routing. Without it, nodes with no public address cannot pull images.
  gcloud compute networks subnets create "$GKE_SUBNET" \
    --network="$PRODUCER_VPC" \
    --region="$REGION" \
    --range="$GKE_SUBNET_RANGE" \
    --secondary-range="pods=${GKE_PODS_RANGE},services=${GKE_SVCS_RANGE}" \
    --enable-private-ip-google-access >/dev/null \
    || die "failed to create $GKE_SUBNET"
  ok "created $GKE_SUBNET ($GKE_SUBNET_RANGE, pods=$GKE_PODS_RANGE, services=$GKE_SVCS_RANGE)"
fi

# --- Subnet 2 of 3: the proxy-only subnet ---
#
# Google Cloud's internal Application Load Balancer is not a box somewhere;
# it is a fleet of Google-managed Envoy proxies. Those proxies need
# addresses inside YOUR network to originate connections to your backends
# from, and that is what this subnet provides.
#
# `--purpose=REGIONAL_MANAGED_PROXY` reserves it for that use. You cannot
# place VMs or forwarding rules in it. One such subnet is required per
# region per VPC that runs an internal ALB, and it is shared by all of them.
#
# `--role=ACTIVE` distinguishes the live subnet from a BACKUP one used when
# migrating proxy subnets. For a single subnet, ACTIVE is what you want.
#
# Forget this subnet and the Gateway in 02 never gets an address, with an
# error that does not obviously point here.
if exists_subnet "$PROXY_SUBNET"; then
  ok "$PROXY_SUBNET already exists"
else
  gcloud compute networks subnets create "$PROXY_SUBNET" \
    --network="$PRODUCER_VPC" \
    --region="$REGION" \
    --range="$PROXY_SUBNET_RANGE" \
    --purpose=REGIONAL_MANAGED_PROXY \
    --role=ACTIVE >/dev/null \
    || die "failed to create $PROXY_SUBNET"
  ok "created $PROXY_SUBNET ($PROXY_SUBNET_RANGE, REGIONAL_MANAGED_PROXY)"
fi

# --- Subnet 3 of 3: the Private Service Connect NAT pool ---
#
# When a consumer connects to a published service, their traffic is source
# NAT'd onto an address from this pool before it reaches the producer's load
# balancer. The producer therefore never sees consumer IP addresses, which
# is deliberate: it means consumer and producer address ranges are allowed
# to overlap, and neither side learns the other's internal addressing.
#
# This has a direct consequence for this demo. The app-tier Cloud Armor
# policy sees addresses from THIS range, not real clients — which is exactly
# why its rate limiting is keyed on `xff-ip` (read from the X-Forwarded-For
# header) rather than on the source IP. See armor.sh.
#
# Like the proxy-only subnet, this one cannot hold VMs or forwarding rules.
# Sizing rule of thumb: one address per connected consumer endpoint, and
# 4 addresses in any subnet are unusable (network, gateway, and two reserved).
if exists_subnet "$PSC_NAT_SUBNET"; then
  ok "$PSC_NAT_SUBNET already exists"
else
  gcloud compute networks subnets create "$PSC_NAT_SUBNET" \
    --network="$PRODUCER_VPC" \
    --region="$REGION" \
    --range="$PSC_NAT_SUBNET_RANGE" \
    --purpose=PRIVATE_SERVICE_CONNECT >/dev/null \
    || die "failed to create $PSC_NAT_SUBNET"
  ok "created $PSC_NAT_SUBNET ($PSC_NAT_SUBNET_RANGE, PRIVATE_SERVICE_CONNECT)"
fi

# =========================================================================
say "Firewall — producer VPC"
# =========================================================================
# A VPC denies all ingress by default, so without these two rules the load
# balancer cannot reach the pods and health checks fail — which presents as
# a load balancer that provisions fine and then serves 502s.

# Rule 1: let the managed Envoy proxies reach the pods. The source is the
# proxy-only subnet range created above, which is where those proxies live.
FW_PROXY="${PREFIX}-allow-proxy-to-pods"
if exists_firewall "$FW_PROXY"; then
  ok "$FW_PROXY already exists"
else
  gcloud compute firewall-rules create "$FW_PROXY" \
    --network="$PRODUCER_VPC" \
    --direction=INGRESS \
    --action=allow \
    --rules="tcp:${APP_PORT},tcp:80,tcp:443" \
    --source-ranges="$PROXY_SUBNET_RANGE" \
    --description="Internal ALB proxy-only subnet to GKE pods" >/dev/null \
    || die "failed to create $FW_PROXY"
  ok "created $FW_PROXY"
fi

# Rule 2: let Google's health check probers in. These two ranges are fixed,
# documented, Google-owned, and identical in every project — memorise them,
# you will type them often. A load balancer marks every backend unhealthy
# and serves 502 if probes cannot reach it, and this missing rule is the
# single most common cause.
FW_HC="${PREFIX}-allow-health-checks"
if exists_firewall "$FW_HC"; then
  ok "$FW_HC already exists"
else
  gcloud compute firewall-rules create "$FW_HC" \
    --network="$PRODUCER_VPC" \
    --direction=INGRESS \
    --action=allow \
    --rules="tcp" \
    --source-ranges="35.191.0.0/16,130.211.0.0/22" \
    --description="Google Cloud health check probers" >/dev/null \
    || die "failed to create $FW_HC"
  ok "created $FW_HC"
fi

# =========================================================================
say "Edge IP"
# =========================================================================
# Reserving a STATIC address, rather than letting the forwarding rule get an
# ephemeral one, means the demo's public IP survives tearing down and
# rebuilding the load balancer. Worth doing for anything you will point DNS
# at, or in this case anything you will paste into slides.
#
# `--global` matters: a global external Application Load Balancer needs a
# global (anycast) address, not a regional one. The same IP is announced
# from Google edge locations worldwide, which is what lets Cloud Armor block
# an attacker at the point of presence nearest to them.
if exists_address "$EDGE_IP_NAME"; then
  ok "$EDGE_IP_NAME already exists"
else
  gcloud compute addresses create "$EDGE_IP_NAME" \
    --global --ip-version=IPV4 >/dev/null \
    || die "failed to reserve $EDGE_IP_NAME"
  ok "reserved $EDGE_IP_NAME"
fi

echo
ok "Edge IP: $(edge_ip)"
echo
echo "Next: ./01-gke.sh"
