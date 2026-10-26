# Demo script — Cloud Armor, live

A walkthrough for presenting this demo to an audience. Seven acts, about 20
minutes. Each act is a few commands and a point to make.

**Before you start**

```bash
./provision-all.sh      # done well in advance — it takes ~30 minutes
./armor.sh reset        # clean slate: everything allowed
./armor.sh status       # confirm, and note your edge IP
```

Open two terminals side by side. Left is where you run commands; right is where
you leave `./logs.sh` ready to run.

**On timing — read this before presenting.** Cloud Armor rule changes are not
instant. Measured on this demo, a toggle took anywhere from 15 seconds to over
3 minutes to be live at the edge, and the SQLi and XSS rules do not propagate
together. Every `armor.sh` toggle therefore blocks until a canary request proves
the change has landed, which means **`./armor.sh waf on` can sit there for three
minutes**. That is normal and it is the honest behaviour — the alternative is
firing `attack.sh` against a stale policy and appearing to have a broken WAF.

Plan for it: say what you are about to change, run the toggle, and talk through
the architecture while it settles. Do not run a toggle and immediately expect to
demo the result.

---

## Act 1 — The application, undefended

> "Here's an ordinary web application on GKE. Nothing in front of it yet."

```bash
./attack.sh baseline
```

All green. Show the app echoing back a request:

```bash
curl "http://$EDGE_IP/?q=savings+account"
```

**The point:** the pods have no public IP and no route from the internet. Traffic
arrives at a global load balancer, crosses into a second VPC over Private Service
Connect, hits an internal load balancer, and only then reaches a pod. The
application is already isolated — but isolation is not filtering.

---

## Act 2 — What "no WAF" actually means

> "Let's see what reaches the application when nothing inspects the traffic."

```bash
./armor.sh waf off
./attack.sh sqli-open
```

Every payload returns **200**. Then show one arriving at the pod:

```bash
curl "http://$EDGE_IP/?q=' OR 1=1 --"
```

The response body contains the payload, echoed back by the pod that received it.

**The point:** that string crossed the internet, the load balancer, the PSC
boundary and the internal load balancer, and was handed to application code. On
this demo app it is harmless. On a real application it is whatever your code does
with it.

**Bonus — show the whole path in one header.** The response includes its own
`X-Forwarded-For`, and it traces every hop:

```
"X-Forwarded-For": "198.51.100.42,203.0.113.10,35.191.99.209,10.10.0.6"
                    │           │           │             │
                    your IP     edge LB     PSC           internal ALB
```

Four addresses, four tiers, in a header the application can read. It is the
clearest single piece of evidence that the architecture is doing what the diagram
claims.

---

## Act 3 — Layer 7: the WAF

> "Two rules, and that stops."

```bash
./armor.sh waf on
./armor.sh status          # show rules 2000 and 2100 appear
./attack.sh sqli xss
```

Twelve payloads, twelve 403s.

**The point:** these are not hand-written patterns. They are the OWASP Core Rule
Set 4.22, maintained by Google, referenced by name:

```
evaluatePreconfiguredWaf('sqli-v422-stable', {'sensitivity': 1})
```

Sensitivity 1 is the conservative setting — fewest false positives — and it still
caught every one. Mention that `sensitivity` is the tuning dial, and individual
signatures can be opted in or out by ID.

Worth saying out loud: the block happens at the Google edge POP nearest the
attacker. The payload never entered either VPC.

---

## Act 4 — Layer 3/4: addresses

> "The WAF inspects content. Sometimes you just want to block a source."

```bash
./armor.sh deny-me
./attack.sh denylist
```

Even the homepage now returns 403 — no inspection involved, the request is
rejected on source address alone.

```bash
./armor.sh undeny-me
```

Then the inverse, default-deny:

```bash
./armor.sh allowlist on
./armor.sh status          # the default rule now reads deny-403
```

You still get 200, because your own IP was added to the allow rule
automatically. Everyone else in the room gets 403.

```bash
./armor.sh allowlist off
```

**The point:** rule priority is the whole model. One ordered list, first match
wins, and the default rule at the bottom decides whether you are running an
allowlist or a denylist.

---

## Act 5 — Geography

```bash
./armor.sh geo             # defaults to your own country
./attack.sh geo
```

403 from your own location.

```bash
./armor.sh geo off
```

**The point:** useful for licensing and compliance boundaries. Note the honest
caveat — geolocation is a database lookup, updated roughly weekly and rolled out
gradually, so it is a policy tool rather than a security boundary.

---

## Act 6 — The second tier: rate limiting

> "Everything so far was at the edge. There's a second policy deeper in."

```bash
./armor.sh status          # point at POLICY 2, the regional one
./attack.sh flood
```

Watch the counter: requests pass, then start returning 429 partway through.

**The point, and this is the most interesting architectural moment in the demo:**
this policy is attached to the *internal* load balancer, by a Kubernetes
`GCPBackendPolicy` manifest rather than by gcloud. And it deliberately contains no
WAF rules — because a regional internal Application Load Balancer cannot enforce
them.

Then show `./logs.sh --app` and point at two fields in the same entry:

```
    client       35.191.117.166:34560          ← what this tier sees
    rate limit   RATE_LIMIT_THRESHOLD_EXCEED  key=198.51.100.42   ← the real client
```

Private Service Connect SNATs traffic, so the internal load balancer sees a
handful of Google proxy addresses rather than real clients. The rule is keyed on
`xff-ip`, which recovers the originating IP from the `X-Forwarded-For` header the
edge load balancer set. Key it on `ip` instead and every user on the internet
collapses into those few proxy addresses — one person tripping the limit would
throttle everybody.

If someone asks why not just put the WAF here too, show them:

```bash
# This is refused, by design
./armor.sh ratelimit on    # works
# armor.sh will not add a WAF rule to the regional policy at all
```

Explain the trap: the manifest *would* apply, `kubectl describe` *would* say
`Attached: True`, and the rules would never fire. Silent non-enforcement. The
script refuses rather than letting you configure a gap you cannot see.

---

## Act 7 — Evidence

> "Every one of those decisions was logged."

```bash
./logs.sh
```

Walk through a single entry:

- `policy` and `priority` — which rule matched
- `action → outcome` — `DENY → DENY`
- `waf rule` — `owasp-crs-v042200-id942140-sqli`, the exact signature
- `matched` — which request field carried the payload, and its value

**The point:** `preconfiguredExprIds` is what you take to a tuning conversation.
When a rule produces a false positive, that ID is what you opt out, rather than
disabling the whole rule set.

Then the rollout pattern:

```bash
./armor.sh waf preview
./attack.sh sqli-open       # 200 — not enforced
./logs.sh --preview         # but logged as would-have-blocked
```

**The point:** this is how you actually deploy a WAF in production. Run it in
preview against real traffic, look at what it *would* have blocked, tune the false
positives, then enforce. Nobody turns a WAF straight on in front of a live
application.

```bash
./armor.sh waf on           # back to enforcing
```

---

## Closing

Three things to leave them with:

1. **Filtering happens at the edge**, at the POP nearest the client — not at your
   VPC, not at your cluster. Blocked traffic consumes nothing of yours.
2. **Layers are a priority-ordered list**, not separate products. Address rules,
   geography, WAF signatures and rate limits are all rules in the same policy,
   evaluated in order.
3. **Where a policy attaches determines what it can do.** A WAF rule on an internal
   load balancer attaches cleanly and silently does nothing. Know the capability
   matrix for the load balancer type you are protecting.

---

## Reset between runs

```bash
./armor.sh reset
```

## Afterwards

```bash
./teardown.sh
```
