# FINDINGS

Found a way past the post? Log it. The bar: get `decide()` to **admit** a request it should refuse — a
capability the operator did not sign, an action outside the grant, past expiry, after revocation, over
budget, or a replayed counter — or get it to **throw** instead of failing closed.

## Report template

```
### <short title>
- Vector:   operator | holder | scope | expiry | revoked | budget | replay | shape | other
- Severity: critical (admits what it should refuse) | high (throws / fails open) | medium | low
- Repro:    the capability + request (JSON), and the ctx (now, spent, lastCounter, revoked)
- Observed: the { admit, stage, reason } decide() returned
```

## In-house intrusions (reproduced by `attack-kit/redteam.mjs --check` — 15 cases, all held)

| Intrusion | Refused at |
|---|---|
| a capability not signed by the operator | `operator` |
| a capability signed by a rogue (unpinned) operator | `operator` |
| a grant tampered after signing — budget bumped | `operator` |
| a grant tampered after signing — actions widened | `operator` |
| a request not signed by the holder (stolen capability) | `holder` |
| a signature reused under a different capability id | `holder` |
| an action the capability does not grant | `scope` |
| an expired capability (now ≥ expiry) | `expiry` |
| a revoked capability | `revoked` |
| over budget (spent + cost > budget) | `budget` |
| a replayed request (counter not advanced) | `replay` |
| a malformed request | `shape` |
| a valid request inside the grant | **admitted** |
| exactly the budget edge (spent + cost == budget) | **admitted** |

## Honest limits

- The post decides authorization; it trusts the **operator key** it is pinned to and the **stores** it is
  handed (the spent ledger, the counter store, the revocation set). Those stores are the deployment's
  responsibility — the post is pure and fails closed if a store returns a non-number.
- `canonical` falls back to a fixed marker on a cycle or a throwing getter rather than throwing; real
  grants/requests are shallow and acyclic, so their serialisation (and signatures) are unaffected.
- No bypass has been produced. If you produce one, log it above.
