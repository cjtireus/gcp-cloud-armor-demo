#!/usr/bin/env bash
# =========================================================================
# 03 — Publish the internal load balancer over Private Service Connect.
#
# WHAT PRIVATE SERVICE CONNECT IS
# PSC lets one VPC reach a single service in another VPC without the two
# networks being connected. That distinction is the whole point:
#
#   VPC peering / VPN  joins two NETWORKS. Routes are exchanged, address
#                      ranges must not overlap, and anything either side
#                      can reach becomes potentially reachable from the
#                      other.
#
#   PSC                publishes one SERVICE. No routes are exchanged,
#                      address ranges may overlap freely, and the consumer
#                      can reach that one endpoint and nothing else.
#
# It is the same model Google uses to offer you Cloud SQL: you get a
# private address for the database, not a route into Google's network.
#
# THE TWO SIDES
#   Producer (this script)  creates a SERVICE ATTACHMENT, which says
#                           "this load balancer is available to consumers"
#   Consumer (04-edge.sh)   creates a PSC NEG pointing at that attachment
#
# In this demo both sides are in one project, which is unusual but valid —
# it keeps the demo to a single project while still crossing a real VPC
# boundary.
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

exists_subnet "$PSC_NAT_SUBNET" || die "NAT subnet '$PSC_NAT_SUBNET' not found. Run ./00-network.sh first."

# =========================================================================
say "Locating the internal ALB forwarding rule"
# =========================================================================
# A service attachment publishes a specific forwarding rule — the frontend
# of the internal load balancer built in step 02.
#
# We did not create that forwarding rule; the GKE Gateway controller did,
# and it chose the name, something like:
#
#   gkegw1-wg77-armor-demo-internal-gateway-cfz09rp36z2b
#
# That suffix is generated, so the name cannot be hardcoded or predicted.
# It must be discovered. Good habit generally: when a controller owns a
# resource, query for it rather than assuming its name.
#
# `mapfile -t ARRAY < <(command)` reads the command's output into a bash
# array, one line per element, with -t stripping trailing newlines. The
# `< <(...)` form is process substitution — it feeds the command's output
# in as if it were a file. A plain pipe would not work here, because a
# pipeline runs its last stage in a subshell and the array would vanish.
mapfile -t FWD_RULES < <(
  # The filter narrows on three things at once:
  #   region                              only this region
  #   loadBalancingScheme=INTERNAL_MANAGED  only internal ALBs (an external
  #                                       one would be EXTERNAL_MANAGED)
  #   network~...$                        `~` is a regex match, `$` anchors
  #                                       the end, so armor-producer-vpc
  #                                       does not also match a longer name
  gcloud compute forwarding-rules list \
    --filter="region:(${REGION}) AND loadBalancingScheme=INTERNAL_MANAGED AND network~${PRODUCER_VPC}$" \
    --format="value(name)" 2>/dev/null
)

# Be strict about the result. Publishing the wrong load balancer would
# silently expose the wrong service, so anything other than exactly one
# match is treated as an error rather than guessed at.
case "${#FWD_RULES[@]}" in   # ${#ARRAY[@]} is the number of elements
  0)
    die "No INTERNAL_MANAGED forwarding rule found in $PRODUCER_VPC/$REGION.
     The Gateway may still be provisioning. Check:
       kubectl -n $APP_NAMESPACE get gateway internal-gateway"
    ;;
  1)
    FWD_RULE="${FWD_RULES[0]}"
    ok "found forwarding rule: $FWD_RULE"
    ;;
  *)
    die "Found ${#FWD_RULES[@]} INTERNAL_MANAGED forwarding rules in $PRODUCER_VPC:
       ${FWD_RULES[*]}
     Cannot decide which to publish. Remove the extras, or set FWD_RULE by hand."
    ;;
esac

# =========================================================================
say "Service attachment — $SERVICE_ATTACHMENT"
# =========================================================================
if exists_attachment "$SERVICE_ATTACHMENT"; then
  ok "$SERVICE_ATTACHMENT already exists"
else
  # --producer-forwarding-rule  the load balancer being published
  #
  # --connection-preference     who may connect:
  #       ACCEPT_AUTOMATIC  any consumer that asks is accepted. Fine here,
  #                         since both sides are the same project.
  #       ACCEPT_MANUAL     each consumer project must be on an allowlist
  #                         (--consumer-accept-list) or is left pending.
  #                         This is what you would use when publishing to
  #                         another organisation.
  #
  # --nat-subnets               the PRIVATE_SERVICE_CONNECT subnet from
  #       step 00. Consumer traffic is source NAT'd onto an address from
  #       here before it reaches the load balancer, which is why the
  #       producer never sees real consumer addresses — and why the
  #       app-tier Cloud Armor policy has to read X-Forwarded-For instead
  #       of the source IP to identify a client.
  gcloud compute service-attachments create "$SERVICE_ATTACHMENT" \
    --region="$REGION" \
    --producer-forwarding-rule="$FWD_RULE" \
    --connection-preference=ACCEPT_AUTOMATIC \
    --nat-subnets="$PSC_NAT_SUBNET" >/dev/null \
    || die "failed to create service attachment"
  ok "created $SERVICE_ATTACHMENT"
fi

echo
# `--format="table(...)"` renders selected fields as a table. `.basename()`
# trims a full resource URI down to just its last path segment, which keeps
# the output readable.
gcloud compute service-attachments describe "$SERVICE_ATTACHMENT" \
  --region="$REGION" \
  --format="table(name, targetService.basename(), connectionPreference, natSubnets.basename())"

echo
# The consumer side needs this URI. Printing it makes the producer/consumer
# handoff explicit — in a real deployment this string is what you would
# send to the team consuming your service.
echo "Service attachment URI:"
echo "  projects/${PROJECT_ID}/regions/${REGION}/serviceAttachments/${SERVICE_ATTACHMENT}"
echo
echo "Next: ./04-edge.sh"
