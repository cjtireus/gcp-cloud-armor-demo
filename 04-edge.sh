#!/usr/bin/env bash
# =========================================================================
# 04 — The edge: a global external Application Load Balancer.
#
# This is the consumer side of the Private Service Connect link, and the
# place Cloud Armor does the interesting work.
#
# WHY "GLOBAL" MATTERS FOR SECURITY
# A global external ALB answers on an anycast IP announced from Google
# points of presence worldwide. A client in Tokyo reaches the Tokyo edge; a
# client in Frankfurt reaches Frankfurt. Cloud Armor rules are enforced
# right there, at whichever edge the request arrives at. A blocked request
# is rejected close to its source and never enters your VPC, never consumes
# your backend capacity, and never crosses an inter-region link you pay for.
#
# WHY THIS IS BUILT BY HAND AND THE INNER ONE IS NOT
# The internal load balancer in step 02 was created by the GKE Gateway
# controller from a YAML manifest. This one is assembled resource by
# resource with gcloud. That is deliberate, and it has a practical
# consequence: no controller owns these resources, so armor.sh can attach
# the security policy with `gcloud ... --security-policy` and nothing will
# reconcile it away. Doing the same to the GKE-managed backend service
# would be reverted on the controller's next sync.
#
# THE FIVE OBJECTS, BOTTOM UP
#   PSC NEG          where traffic goes (the published service)
#   backend service  the pool, plus logging and the Cloud Armor policy
#   URL map          routing rules
#   target proxy     speaks HTTP, consults the URL map
#   forwarding rule  the public IP and port clients connect to
# Each points at the one before it, so they must be created in this order.
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

exists_attachment "$SERVICE_ATTACHMENT" \
  || die "Service attachment '$SERVICE_ATTACHMENT' not found. Run ./03-psc-publish.sh first."
EDGE_IP="$(require_edge_ip)"

# Resource URIs follow a predictable shape. Regional resources are
# projects/PROJECT/regions/REGION/TYPE/NAME; global ones use /global/
# instead of /regions/REGION.
ATTACHMENT_URI="projects/${PROJECT_ID}/regions/${REGION}/serviceAttachments/${SERVICE_ATTACHMENT}"

# =========================================================================
say "Private Service Connect NEG — $PSC_NEG"
# =========================================================================
# A Network Endpoint Group is a load balancer's list of "things to send
# traffic to". There are several kinds — VM IP and port, serverless,
# internet FQDN — and this one has type `private-service-connect`, meaning
# the endpoint is a published service rather than any machine we own.
#
# The NEG consumes one /32 from the consumer subnet, which the load
# balancer uses as its source address when talking across the PSC link.
if exists_neg "$PSC_NEG"; then
  ok "$PSC_NEG already exists"
else
  gcloud compute network-endpoint-groups create "$PSC_NEG" \
    --region="$REGION" \
    --network-endpoint-type=private-service-connect \
    --psc-target-service="$ATTACHMENT_URI" \
    --network="$CONSUMER_VPC" \
    --subnet="$CONSUMER_SUBNET" >/dev/null \
    || die "failed to create PSC NEG"
  ok "created $PSC_NEG → $SERVICE_ATTACHMENT"
fi

# =========================================================================
say "Backend service — $EDGE_BACKEND"
# =========================================================================
# The backend service is the most important object in a Google Cloud load
# balancer. It owns the backend list, health checking, timeouts, logging,
# Cloud CDN — and the Cloud Armor security policy. When you "attach Cloud
# Armor to a load balancer", this is the object you actually attach it to.
if exists_backend "$EDGE_BACKEND"; then
  ok "$EDGE_BACKEND already exists"
else
  # --load-balancing-scheme=EXTERNAL_MANAGED selects the modern global
  # external ALB. (EXTERNAL is the older classic one; INTERNAL_MANAGED is
  # the internal flavour used by the Gateway in step 02.)
  #
  # NO HEALTH CHECK, deliberately. Every other backend type requires one
  # and refuses to be created without it. PSC NEG backends do not support
  # health checks at all — nor session affinity — because the producer's
  # own load balancer is already health checking the real backends. Adding
  # `--health-checks` here fails.
  gcloud compute backend-services create "$EDGE_BACKEND" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --protocol=HTTP >/dev/null \
    || die "failed to create backend service"
  ok "created $EDGE_BACKEND"
fi

# Adding a backend twice is an error rather than a no-op, so check first.
# This grep looks for the NEG name in the existing backend list, keeping
# the script re-runnable.
if gcloud compute backend-services describe "$EDGE_BACKEND" --global \
     --format="value(backends[].group)" 2>/dev/null | grep -q "$PSC_NEG"; then
  ok "PSC NEG already attached as a backend"
else
  # The NEG is regional while the backend service is global, so both
  # scopes have to be named: --global for the backend service,
  # --network-endpoint-group-region for the NEG.
  gcloud compute backend-services add-backend "$EDGE_BACKEND" \
    --global \
    --network-endpoint-group="$PSC_NEG" \
    --network-endpoint-group-region="$REGION" >/dev/null \
    || die "failed to add PSC NEG backend"
  ok "attached $PSC_NEG as a backend"
fi

# Cloud Armor does not have its own log stream. Its decisions are recorded
# as extra fields inside the load balancer's request logs, so if request
# logging is off, ./logs.sh finds nothing and the demo looks broken.
# Sample rate 1.0 means 100%; reduce it on a busy production service.
gcloud compute backend-services update "$EDGE_BACKEND" \
  --global --enable-logging --logging-sample-rate=1.0 >/dev/null 2>&1 \
  && ok "request logging enabled at 100%" \
  || warn "could not enable request logging"

# =========================================================================
say "URL map, proxy and forwarding rule"
# =========================================================================
# The URL map is the routing table: host and path rules deciding which
# backend service handles a request. This demo has one backend, so it is
# just a default. A real one might route /api to one service and
# /static to a storage bucket.
if exists_url_map "$EDGE_URL_MAP"; then
  ok "$EDGE_URL_MAP already exists"
else
  gcloud compute url-maps create "$EDGE_URL_MAP" \
    --global --default-service="$EDGE_BACKEND" >/dev/null \
    || die "failed to create url map"
  ok "created $EDGE_URL_MAP"
fi

# The target proxy terminates the client connection and consults the URL
# map. A target HTTPS proxy would be the same object plus certificates;
# everything downstream of it is identical, which is why switching this
# demo to HTTPS would not touch the backend service or the Cloud Armor
# configuration at all.
if exists_proxy "$EDGE_PROXY"; then
  ok "$EDGE_PROXY already exists"
else
  gcloud compute target-http-proxies create "$EDGE_PROXY" \
    --global --url-map="$EDGE_URL_MAP" >/dev/null \
    || die "failed to create target proxy"
  ok "created $EDGE_PROXY"
fi

# The forwarding rule binds an IP and port to the proxy. This is the only
# part of the chain clients ever see; everything above is internal
# plumbing. Creating it is what makes the load balancer live.
if exists_fwd_rule "$EDGE_FWD_RULE"; then
  ok "$EDGE_FWD_RULE already exists"
else
  gcloud compute forwarding-rules create "$EDGE_FWD_RULE" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --address="$EDGE_IP_NAME" \
    --target-http-proxy="$EDGE_PROXY" \
    --ports=80 >/dev/null \
    || die "failed to create forwarding rule"
  ok "created $EDGE_FWD_RULE on $EDGE_IP:80"
fi

# =========================================================================
say "Attaching the edge Cloud Armor policy"
# =========================================================================
# One line, and it is the entire point of the demo. A security policy is an
# independent resource; attaching it to a backend service is what puts it
# in the request path. The same policy can protect several backend
# services, and detaching it is equally one command — which makes
# before/after comparisons easy.
if exists_policy "$EDGE_POLICY"; then
  gcloud compute backend-services update "$EDGE_BACKEND" \
    --global --security-policy="$EDGE_POLICY" >/dev/null \
    || die "failed to attach $EDGE_POLICY"
  ok "attached $EDGE_POLICY to $EDGE_BACKEND"
else
  warn "Policy '$EDGE_POLICY' not found — run ./armor.sh create, then re-run this script."
fi

# =========================================================================
say "Waiting for the edge to serve"
# =========================================================================
# A new global forwarding rule has to propagate to Google edge locations
# worldwide, which takes a few minutes. During that window requests may
# return 404 or 502. That is expected, not a misconfiguration — so poll
# until a real request succeeds rather than declaring victory immediately.
edge_serves() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${EDGE_IP}/" 2>/dev/null)"
  [[ "$code" == "200" ]]
}

echo "  a new global forwarding rule takes 5-10 minutes to propagate"
if wait_for 900 "edge LB to return 200" edge_serves; then
  ok "end-to-end path is live"
else
  # If this fails, the hint matters: the request crosses four tiers, and
  # knowing the order is how you work out which one broke.
  warn "no 200 yet. The path is edge LB → PSC NEG → service attachment → internal ALB → GKE."
  warn "Check the PSC connection state with:"
  warn "  gcloud compute service-attachments describe $SERVICE_ATTACHMENT --region=$REGION"
  warn "  (look for connectedEndpoints[].status: ACCEPTED)"
fi

echo
echo "=========================================================="
echo "  Edge IP:  http://${EDGE_IP}/"
echo "=========================================================="
echo
echo "Next: ./attack.sh baseline"
