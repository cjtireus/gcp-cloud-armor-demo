#!/usr/bin/env bash
# =========================================================================
# provision-all.sh — build the whole demo, in order.
#
# The steps are not interchangeable:
#   00  networks must exist before the cluster can join one
#   01  the cluster must exist before anything is deployed to it
#   --  the policies must exist before 02, because GCPBackendPolicy names one
#   02  the Gateway must finish before its forwarding rule can be published
#   03  the attachment must exist before a PSC NEG can point at it
#   04  the NEG must exist before the edge load balancer can use it
#
# Roughly 25-30 minutes end to end, most of it waiting on the GKE cluster
# and the two load balancers.
# =========================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# step <heading> <command...>
#
# Print a banner, run the command, and stop the whole build if it fails.
# The hint about idempotency is the important part: every script here can
# safely be re-run, so a failure at step 04 does not mean starting over.
# Fix the cause and run provision-all.sh again — the earlier steps will
# recognise their resources already exist and skip straight past them.
step() {
  echo
  echo "##############################################################################"
  echo "#  $1"
  echo "##############################################################################"
  shift
  "$@" || { echo -e "\nFAILED: $*\nFix the problem and re-run ./provision-all.sh — every step is idempotent." >&2; exit 1; }
}

# $SECONDS is a bash builtin that counts seconds since the shell started.
# Capturing it here and subtracting later gives the elapsed time for free.
START="$SECONDS"

step "00 — networks"                  "$HERE/00-network.sh"
step "01 — GKE Autopilot cluster"     "$HERE/01-gke.sh"
step "armor — create both policies"   "$HERE/armor.sh" create
step "02 — app and internal Gateway"  "$HERE/02-app.sh"
step "03 — publish over PSC"          "$HERE/03-psc-publish.sh"
step "04 — edge load balancer"        "$HERE/04-edge.sh"

ELAPSED=$(( SECONDS - START ))

cat <<EOF

##############################################################################
#  Done in $(( ELAPSED / 60 ))m $(( ELAPSED % 60 ))s
##############################################################################

  ./armor.sh status      see both policies and their attachments
  ./attack.sh baseline   confirm legitimate traffic passes
  ./attack.sh sqli xss   confirm the WAF blocks attacks
  ./logs.sh              see what Cloud Armor recorded

  docs/DEMO_SCRIPT.md    the walkthrough for a live audience

  ./teardown.sh          delete everything when you are finished

EOF
