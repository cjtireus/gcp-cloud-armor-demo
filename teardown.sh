#!/usr/bin/env bash
# =========================================================================
# teardown.sh — delete everything, in an order the dependencies allow.
#
# WHY ORDER MATTERS SO MUCH HERE
# Google Cloud refuses to delete a resource that another resource still
# references. Load balancers are a chain of five objects each pinning the
# next, so deleting from the wrong end fails on every single one:
#
#   forwarding rule → target proxy → URL map → backend service → NEG
#
# Private Service Connect adds another: a service attachment will not
# delete while a consumer endpoint is still connected, and subnets will
# not delete while anything lives in them. So teardown is strictly the
# build order reversed.
#
# WHY NOTHING ABORTS ON FAILURE
# Every delete goes through try(), which reports and carries on. A partial
# teardown is common — something may have been deleted manually, or a
# dependency may still be clearing — and stopping at the first failure
# would strand everything after it. Run the script twice if needed; the
# second pass usually clears whatever was still pinned on the first.
#
# Usage: ./teardown.sh [--yes]
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

ASSUME_YES=false
[[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]] && ASSUME_YES=true

cat <<EOF

==============================================================================
  Tearing down the Cloud Armor demo
  project $PROJECT_ID   region $REGION
==============================================================================

This deletes:
  - the edge load balancer  ($EDGE_FWD_RULE, $EDGE_PROXY, $EDGE_URL_MAP, $EDGE_BACKEND)
  - the PSC NEG and service attachment  ($PSC_NEG, $SERVICE_ATTACHMENT)
  - the GKE cluster  ($CLUSTER_NAME)  and everything running on it
  - both VPCs and all their subnets  ($CONSUMER_VPC, $PRODUCER_VPC)
  - the reserved edge IP  ($EDGE_IP_NAME)
  - the geo probe VM and its VPC, if 05-geo-probe.sh was ever run
  - both Cloud Armor policies  ($EDGE_POLICY, $APP_POLICY)

EOF

if ! $ASSUME_YES; then
  read -r -p "Type 'delete' to continue: " CONFIRM
  [[ "$CONFIRM" == "delete" ]] || { echo "Aborted."; exit 0; }
fi

# try <description> <command...>
#
# Run a delete, report what happened, and never abort. "$@" after the
# description shift is the command to execute. Redirecting both stdout and
# stderr to /dev/null keeps the output readable — gcloud is verbose about
# resources that are already gone, and that is not an error here.
try() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else echo "  · skipped: $desc"; fi
}

# =========================================================================
say "1/7  Edge load balancer"
# =========================================================================
# Front to back. Each of these pins the next, so the order is not optional:
# you cannot delete the target proxy while a forwarding rule points at it.
try "forwarding rule $EDGE_FWD_RULE" \
  gcloud compute forwarding-rules delete "$EDGE_FWD_RULE" --global --quiet
try "target proxy $EDGE_PROXY" \
  gcloud compute target-http-proxies delete "$EDGE_PROXY" --global --quiet
try "url map $EDGE_URL_MAP" \
  gcloud compute url-maps delete "$EDGE_URL_MAP" --global --quiet
try "backend service $EDGE_BACKEND" \
  gcloud compute backend-services delete "$EDGE_BACKEND" --global --quiet

# =========================================================================
say "2/7  Private Service Connect"
# =========================================================================
# The NEG is the consumer end of the PSC link and must go first. While it
# exists the service attachment has a live connected endpoint and will
# refuse to delete. Deleting the NEG is also asynchronous, which is why
# the wait below exists rather than deleting both back to back.
try "PSC NEG $PSC_NEG" \
  gcloud compute network-endpoint-groups delete "$PSC_NEG" --region="$REGION" --quiet

if exists_attachment "$SERVICE_ATTACHMENT"; then
  # Deleting the NEG is asynchronous; give the connection time to drop.
  attachment_free() {
    local n
    n="$(gcloud compute service-attachments describe "$SERVICE_ATTACHMENT" \
          --region="$REGION" --format="value(connectedEndpoints)" 2>/dev/null)"
    [[ -z "$n" ]]
  }
  wait_for 180 "the attachment's connected endpoint to drop" attachment_free || \
    warn "still shows a connected endpoint; the delete below may fail"
fi

try "service attachment $SERVICE_ATTACHMENT" \
  gcloud compute service-attachments delete "$SERVICE_ATTACHMENT" --region="$REGION" --quiet

# =========================================================================
say "3/7  Kubernetes resources"
# =========================================================================
# Delete the Kubernetes objects BEFORE the cluster.
#
# The internal load balancer was created by the Gateway controller, which
# runs in the cluster. Deleting the Gateway lets that controller clean up
# the load balancer it owns. Delete the cluster first and the controller
# disappears along with it, leaving orphaned forwarding rules and backend
# services behind — which then block the subnet and VPC deletes, with an
# error that does not explain why.
#
# General rule: let the controller that created a cloud resource be the
# one that deletes it.
if exists_cluster; then
  if gcloud container clusters get-credentials "$CLUSTER_NAME" \
       --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
    try "namespace $APP_NAMESPACE (Gateway, app, policies)" \
      kubectl delete namespace "$APP_NAMESPACE" --timeout=300s

    ilb_gone() {
      local n
      n="$(gcloud compute forwarding-rules list \
            --filter="region:(${REGION}) AND loadBalancingScheme=INTERNAL_MANAGED AND network~${PRODUCER_VPC}$" \
            --format="value(name)" 2>/dev/null | wc -l)"
      [[ "$n" -eq 0 ]]
    }
    wait_for 300 "the internal ALB to be released" ilb_gone || \
      warn "an internal forwarding rule survives; the subnet delete may fail"
  else
    warn "could not reach the cluster; skipping the Kubernetes cleanup"
  fi
else
  echo "  · skipped: cluster not found"
fi

# =========================================================================
say "4/7  GKE cluster"
# =========================================================================
try "cluster $CLUSTER_NAME" \
  gcloud container clusters delete "$CLUSTER_NAME" --location="$REGION" --quiet

# =========================================================================
say "5/7  Subnets and firewall rules"
# =========================================================================
try "firewall ${PREFIX}-allow-proxy-to-pods" \
  gcloud compute firewall-rules delete "${PREFIX}-allow-proxy-to-pods" --quiet
try "firewall ${PREFIX}-allow-health-checks" \
  gcloud compute firewall-rules delete "${PREFIX}-allow-health-checks" --quiet

# GKE leaves its own firewall rules behind, named after the cluster.
mapfile -t GKE_FW < <(
  gcloud compute firewall-rules list \
    --filter="network~${PRODUCER_VPC}$" --format="value(name)" 2>/dev/null
)
for fw in "${GKE_FW[@]}"; do
  [[ -n "$fw" ]] && try "firewall $fw (GKE-managed)" \
    gcloud compute firewall-rules delete "$fw" --quiet
done

# The PSC NAT subnet must outlive the attachment, and the proxy-only subnet
# must outlive the internal ALB — both are gone by now.
for sn in "$PSC_NAT_SUBNET" "$PROXY_SUBNET" "$GKE_SUBNET" "$CONSUMER_SUBNET"; do
  try "subnet $sn" \
    gcloud compute networks subnets delete "$sn" --region="$REGION" --quiet
done

# =========================================================================
say "5b/7  Geo probe (optional, created by 05-geo-probe.sh)"
# =========================================================================
# Independent of everything above — its own VPC, nothing else references
# it. Skipped silently if 05-geo-probe.sh was never run.
try "probe VM $PROBE_VM" \
  gcloud compute instances delete "$PROBE_VM" --zone="$PROBE_ZONE" --quiet
try "firewall ${PREFIX}-probe-allow-iap-ssh" \
  gcloud compute firewall-rules delete "${PREFIX}-probe-allow-iap-ssh" --quiet
try "subnet $PROBE_SUBNET" \
  gcloud compute networks subnets delete "$PROBE_SUBNET" --region="$PROBE_REGION" --quiet
try "network $PROBE_VPC" \
  gcloud compute networks delete "$PROBE_VPC" --quiet

# =========================================================================
say "6/7  VPCs and the edge IP"
# =========================================================================
try "network $PRODUCER_VPC" gcloud compute networks delete "$PRODUCER_VPC" --quiet
try "network $CONSUMER_VPC" gcloud compute networks delete "$CONSUMER_VPC" --quiet
try "address $EDGE_IP_NAME"  gcloud compute addresses delete "$EDGE_IP_NAME" --global --quiet

# =========================================================================
say "7/7  Cloud Armor policies"
# =========================================================================
# Last, because a security policy cannot be deleted while any backend
# service still references it — and those were only removed in step 1.
try "policy $EDGE_POLICY" \
  gcloud compute security-policies delete "$EDGE_POLICY" --global --quiet
try "policy $APP_POLICY" \
  gcloud compute security-policies delete "$APP_POLICY" --region="$REGION" --quiet

rm -f "$KUBECONFIG"

# =========================================================================
say "Remaining demo resources"
# =========================================================================
echo "Security policies:"
gcloud compute security-policies list --format="value(name)" 2>/dev/null | sed 's/^/  /' || true
echo "Global addresses:"
gcloud compute addresses list --global --format="value(name)" 2>/dev/null | sed 's/^/  /' || true
echo "Clusters:"
gcloud container clusters list --format="value(name)" 2>/dev/null | sed 's/^/  /' || true
echo "Networks:"
gcloud compute networks list --format="value(name)" 2>/dev/null | sed 's/^/  /' || true
echo "Service attachments:"
gcloud compute service-attachments list --format="value(name)" 2>/dev/null | sed 's/^/  /' || true

echo
ok "Teardown finished. Anything listed above that belongs to this demo did not delete —"
echo "  re-run ./teardown.sh; dependencies often clear on a second pass."
