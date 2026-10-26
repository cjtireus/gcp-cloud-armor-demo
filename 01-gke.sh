#!/usr/bin/env bash
# =========================================================================
# 01 — The GKE cluster.
#
# Creates a GKE Autopilot cluster inside the producer VPC, then checks that
# the Gateway API is ready to use.
#
# AUTOPILOT vs STANDARD
# GKE has two modes. In Standard you create and manage node pools: you pick
# machine types, counts, and autoscaling, and you pay for the nodes whether
# or not anything is running on them. In Autopilot, Google manages the nodes
# entirely and you pay per pod for the CPU and memory you request. For a
# demo with two small pods, Autopilot is simpler and cheaper, and it has the
# Gateway API enabled out of the box.
#
# WHAT THE GATEWAY API IS
# Gateway API is the successor to Kubernetes Ingress. You declare a Gateway
# (a load balancer) and HTTPRoutes (routing rules) as Kubernetes objects,
# and a controller creates the real cloud load balancer to match. A
# GatewayClass names which kind of load balancer you want. The one used
# here, gke-l7-rilb, builds a regional INTERNAL Application Load Balancer —
# the "rilb" in the name.
#
# Takes roughly 8 minutes. Most of that is the cluster; nothing is wrong.
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# Fail early with a useful message rather than letting gcloud fail obscurely
# halfway through an 8-minute operation.
exists_subnet "$GKE_SUBNET" || die "Subnet '$GKE_SUBNET' not found. Run ./00-network.sh first."

# =========================================================================
say "GKE Autopilot cluster — $CLUSTER_NAME"
# =========================================================================
if exists_cluster; then
  ok "$CLUSTER_NAME already exists"
else
  echo "  creating (this takes ~8 minutes)..."
  # Flag by flag:
  #   create-auto                     Autopilot mode (vs plain `create`)
  #   --location=REGION               a regional cluster: the control plane
  #                                   is replicated across zones. Passing a
  #                                   zone instead would make it zonal and
  #                                   cheaper, but with a single point of
  #                                   failure for the control plane.
  #   --network / --subnetwork        place it in the VPC built in step 00,
  #                                   NOT the project's default network
  #   --cluster-secondary-range-name  the "pods" secondary range from 00
  #   --services-secondary-range-name the "services" secondary range from 00
  #   --release-channel=regular       Google handles version upgrades.
  #                                   regular balances new features against
  #                                   stability; rapid and stable are the
  #                                   other options.
  gcloud container clusters create-auto "$CLUSTER_NAME" \
    --location="$REGION" \
    --network="$PRODUCER_VPC" \
    --subnetwork="$GKE_SUBNET" \
    --cluster-secondary-range-name=pods \
    --services-secondary-range-name=services \
    --release-channel=regular \
    || die "cluster creation failed"
  ok "created $CLUSTER_NAME"
fi

# =========================================================================
say "Cluster credentials"
# =========================================================================
# This writes an entry into the kubeconfig file so kubectl knows the
# cluster's API server address and how to authenticate to it. Recall that
# lib.sh pointed $KUBECONFIG at a file inside this repo, so this cannot
# disturb your existing kubectl contexts.
gcloud container clusters get-credentials "$CLUSTER_NAME" \
  --location="$REGION" --project="$PROJECT_ID" 2>&1 | tail -1
ok "kubeconfig written to $KUBECONFIG"

# =========================================================================
say "Verifying Gateway API"
# =========================================================================
# GatewayClasses are installed by a controller shortly AFTER the cluster
# reports itself ready, so there is a window where the cluster is RUNNING
# but `kubectl get gatewayclass` returns nothing. Checking here, instead of
# letting 02-app.sh fail, makes the cause obvious.
if ! kubectl get gatewayclass gke-l7-rilb &>/dev/null; then
  warn "GatewayClass gke-l7-rilb not found yet."
  wait_for 300 "GatewayClass gke-l7-rilb" kubectl get gatewayclass gke-l7-rilb \
    || die "GatewayClass gke-l7-rilb never appeared. Check: kubectl get gatewayclass"
fi

# Existing is not the same as usable. A GatewayClass carries a status
# condition named "Accepted"; until that is True the controller will not act
# on Gateways referencing it.
#
# The jsonpath filter `[?(@.type=="Accepted")]` selects the array element
# whose `type` field equals "Accepted", then `.status` reads its value.
# jsonpath is worth learning — it is how you pull single fields out of
# Kubernetes objects in scripts.
ACCEPTED="$(kubectl get gatewayclass gke-l7-rilb \
  -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null)"
[[ "$ACCEPTED" == "True" ]] || die "GatewayClass gke-l7-rilb is not Accepted (status=$ACCEPTED)"
ok "GatewayClass gke-l7-rilb is Accepted"

echo
echo "Next: ./armor.sh create   (the policies must exist before the app is deployed,"
echo "                           because GCPBackendPolicy references one by name)"
echo "Then: ./02-app.sh"
