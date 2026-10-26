#!/usr/bin/env bash
# =========================================================================
# 02 — Deploy the app and the internal load balancer.
#
# Renders the YAML in k8s/ with values from config.env, applies it, then
# waits for GKE to finish building the real load balancer behind the
# Gateway object.
#
# ORDER DEPENDENCY: ./armor.sh create must have run first. The
# GCPBackendPolicy in k8s/gateway.yaml names a Cloud Armor policy, and
# attaching a policy that does not exist fails.
#
# The Gateway takes up to 10 minutes. Applying the YAML returns in seconds,
# but that only records your intent in the Kubernetes API — a controller
# then provisions the actual cloud load balancer in the background. This is
# the central idea of Kubernetes: you declare desired state, a controller
# reconciles reality towards it, and the two are not simultaneous.
# =========================================================================
set -uo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

kube_creds   # from lib.sh: makes sure kubectl can talk to the cluster

exists_policy "$APP_POLICY" "$REGION" \
  || die "Regional policy '$APP_POLICY' not found. Run ./armor.sh create first."

# Render the manifests into a scratch directory rather than editing the
# files in k8s/, so the repo stays clean and the templates stay templates.
#
# `mktemp -d` creates a uniquely named temp directory. The `trap` runs the
# cleanup when the script exits for ANY reason — success, error, or Ctrl-C.
# Setting a trap immediately after creating a temp directory is a habit
# worth forming.
RENDER_DIR="$(mktemp -d)"
trap 'rm -rf "$RENDER_DIR"' EXIT

# Substitute the __PLACEHOLDER__ tokens with real values.
#
# `sed -e 's|FIND|REPLACE|g'` substitutes globally. The delimiter here is
# `|` rather than the usual `/` because some values are container image
# paths containing slashes, which would otherwise end the expression early.
# You can use almost any character as the sed delimiter; pick one that does
# not appear in your data.
#
# For anything more involved than this, reach for Kustomize or Helm rather
# than growing a sed pipeline.
render() {
  sed -e "s|__NAMESPACE__|${APP_NAMESPACE}|g" \
      -e "s|__APP__|${APP_NAME}|g" \
      -e "s|__IMAGE__|${APP_IMAGE}|g" \
      -e "s|__PORT__|${APP_PORT}|g" \
      -e "s|__APP_POLICY__|${APP_POLICY}|g" \
      "$HERE/k8s/$1" > "$RENDER_DIR/$1"
}

# =========================================================================
say "Deploying $APP_NAME to namespace $APP_NAMESPACE"
# =========================================================================
render app.yaml
# `kubectl apply` is declarative: it creates objects that do not exist and
# updates those that do, which is what makes re-running this script safe.
# Contrast with `kubectl create`, which errors if the object already exists.
kubectl apply -f "$RENDER_DIR/app.yaml" || die "failed to apply app.yaml"

# `rollout status` blocks until the Deployment's pods are actually ready,
# rather than returning the instant the object is created. On Autopilot the
# first rollout is slower than usual because nodes are provisioned on demand.
echo "  waiting for pods..."
kubectl -n "$APP_NAMESPACE" rollout status "deployment/$APP_NAME" --timeout=300s \
  || die "deployment did not become ready"
ok "$APP_NAME is running"

# =========================================================================
say "Internal Gateway + Cloud Armor attachment"
# =========================================================================
render gateway.yaml
kubectl apply -f "$RENDER_DIR/gateway.yaml" || die "failed to apply gateway.yaml"
ok "manifests applied"

# The Gateway controller reports progress by writing to the object's
# `status` field. An address appearing there means the load balancer exists
# and has an IP. Polling for that is far more reliable than sleeping for a
# fixed time and hoping.
#
# This is defined as a function so it can be passed to wait_for, which
# calls it repeatedly until it succeeds.
gateway_has_address() {
  local addr
  addr="$(kubectl -n "$APP_NAMESPACE" get gateway internal-gateway \
    -o jsonpath='{.status.addresses[0].value}' 2>/dev/null)"
  [[ -n "$addr" ]]   # the function's exit status is this test's result
}

echo "  the internal load balancer takes up to 10 minutes to provision"
wait_for 900 "internal Gateway address" gateway_has_address \
  || die "Gateway never got an address. Check: kubectl -n $APP_NAMESPACE describe gateway internal-gateway"

ILB_ADDR="$(kubectl -n "$APP_NAMESPACE" get gateway internal-gateway \
  -o jsonpath='{.status.addresses[0].value}')"
ok "internal ALB address: $ILB_ADDR"

# =========================================================================
say "Verifying the Cloud Armor attachment"
# =========================================================================
# A GCPBackendPolicy reports whether it successfully bound to its target
# through an "Attached" status condition. Worth checking explicitly: a
# policy that failed to attach leaves the backend unprotected while the
# manifest sits in the cluster looking perfectly fine.
ATTACHED="$(kubectl -n "$APP_NAMESPACE" get gcpbackendpolicy "${APP_NAME}-armor" \
  -o jsonpath='{.status.conditions[?(@.type=="Attached")].status}' 2>/dev/null)"
if [[ "$ATTACHED" == "True" ]]; then
  ok "GCPBackendPolicy attached $APP_POLICY to the app backend service"
else
  # A warning rather than a fatal error: this often settles a minute after
  # the Gateway, and stopping the build here would be unhelpful.
  warn "GCPBackendPolicy not yet Attached (status=${ATTACHED:-unknown})."
  warn "It often settles a minute after the Gateway. Re-check with:"
  warn "  kubectl -n $APP_NAMESPACE describe gcpbackendpolicy ${APP_NAME}-armor"
fi

# =========================================================================
say "End-to-end check from inside the cluster"
# =========================================================================
# The internal load balancer has a private address, so it can only be
# reached from inside the VPC. Running a throwaway curl pod is the simplest
# way to test from in there.
#
# Proving the app answers HERE, before Private Service Connect is involved,
# is deliberate: if the public endpoint later fails, you already know the
# problem is in the PSC hop or the edge load balancer, not in the app.
# Narrowing a four-tier path one tier at a time beats guessing.
#
#   --rm            delete the pod when it finishes
#   --restart=Never run once, do not treat it as a long-running workload
#   --command --    everything after this is the command, not kubectl flags
if kubectl -n "$APP_NAMESPACE" run armor-curl-check \
     --rm -i --restart=Never --image=curlimages/curl:8.10.1 --quiet \
     --command -- curl -fsS --max-time 15 "http://${ILB_ADDR}/" >/dev/null 2>&1; then
  ok "app responds through the internal ALB"
else
  warn "in-cluster curl did not succeed yet — the ALB may still be warming up"
fi

echo
echo "Next: ./03-psc-publish.sh"
