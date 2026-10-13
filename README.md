# PERIMETER POST

### ▶ Live: **https://sjgant80-hub.github.io/perimeter-post/**

The **authorization checkpoint** for kar-hub. A packet gate asks *"is this message well-formed and
authentic?"* — this asks **"is this agent authorised and in budget for *this* action, right now?"**

An **operator** issues a **capability**: a holder key may do these *actions*, up to this *budget*, until
this *expiry*, under an *id* (so it can be revoked). An **agent** presents a **request** — an action, a
cost, a fresh counter — signed by the holder, carrying the capability. The post admits it **only if**, in
order, fail-closed:

```
operator-signed → holder-signed → in scope → not expired → not revoked → in budget → not a replay → ADMIT
```

Both the capability and the request are signed over a domain-separated, canonical serialisation of their
exact fields, so neither can be tampered after signing (bump the budget, widen the actions, swap the
holder) without breaking the signature.

> Chosen by **Kar's own local 14B** as the next organ, from its nightly dream graph — the recurring
> *"perimeter around kar-hub, operator-controlled access."*

## Run it

```bash
node run.mjs    # the operator issues a capability; an agent reads/writes within it; every intrusion is refused
```

## Proof it holds (all re-runnable; CI runs them)

- **`node attack-kit/redteam.mjs --check`** — 15 simulated intrusions, byte-identical receipt: a forged
  grant, a rogue operator, a grant tampered after signing (budget bumped / actions widened), a stolen
  capability, an over-scope action, an expired one, a revoked one, over budget, a replay — all refused at
  the right stage; a valid agent gets in within its grant.
- **`node witness-all.mjs`** — mutation + fuzz gate over `token` and `post`: **CLEAN, 68/68 killed, zero
  baselined.** (The fuzz caught two real total-ness gaps — a BigInt and a throwing getter — before the gate
  ran; both fixed, then a green baseline makes the score mean something.)
- **`node --test test/*.test.mjs`** — unit + hostile-input (never-throw) suites.

## Composes with the rest of the rail

- **[break-it](https://github.com/sjgant80-hub/break-it)** — the packet gate (authenticity). Perimeter Post
  is the authorization layer above it: break-it proves *the message is real*, the post decides *this agent
  may do this*.
- **[immune-exchange](https://github.com/sjgant80-hub/immune-exchange)** — a refusal here is an antigen too;
  a forged or stolen-capability attempt can feed the bus.

Identity is a capability plus a budget, issued by an operator, spent by a holder. MIT licensed; see
[`NOTICE`](NOTICE) for credits. Keys live in `secrets/` (git-ignored, never served).
