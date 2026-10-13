// ════════════════════════════════════════════════════════════════
// post.mjs — THE PERIMETER POST. The checkpoint in front of kar-hub. Pure, total, fail-closed.
//
// It answers a different question from a packet gate: not "is this message well-formed and authentic?" but "is this
// agent AUTHORISED and IN BUDGET for THIS action, right now?". In order, on the request, nothing acted on until all
// pass:
//   1 shape     — the request and its embedded capability are well-formed (token.validRequest)
//   2 operator  — the capability is signed by the PINNED operator key (only the operator may grant)
//   3 holder    — the request is signed by the capability's holder key (only the holder may spend it)
//   4 scope     — the requested action is one the capability grants
//   5 expiry    — the capability has not expired (now < expiry)
//   6 revoked   — the operator has not revoked this capability id
//   7 budget    — the cost fits what is left of the capability's budget (spent + cost ≤ budget)
//   8 replay    — the request counter is strictly after this holder's last admitted counter
//   then, and only then: ADMIT, and tell the caller the cost to charge against the capability.
//
// Everything is injected (the operator key, verify, the clock, the spent/last-counter/revoked stores), so this
// file has no I/O, no clock and no crypto of its own: the same request and the same state give the same verdict on
// every machine. Any exception anywhere is a refusal — there is no path on which a failure admits.
// ════════════════════════════════════════════════════════════════
import { validRequest, capMaterial, reqMaterial } from './token.mjs';

export const STAGES = Object.freeze(['shape', 'operator', 'holder', 'scope', 'expiry', 'revoked', 'budget', 'replay', 'admitted']);
const no = (stage, reason) => Object.freeze({ admit: false, stage, reason });

/**
 * ctx: { operatorKey (hex), verify(messageStr, sigHex, pubHex) → boolean (sync, never throws),
 *        now() → integer epoch, spent(capId) → integer already spent, lastCounter(holder) → integer,
 *        revoked(capId) → boolean }
 * → { admit:true, stage:'admitted', holder, id, action, cost } | { admit:false, stage, reason }
 */
export function decide(request, ctx) {
  try {
    if (!validRequest(request)) return no('shape', 'the request or its capability is malformed');
    const cap = request.capability, g = cap.grant;
    if (ctx.verify(capMaterial(g), cap.sig, ctx.operatorKey) !== true) return no('operator', 'the capability is not signed by the operator');
    if (ctx.verify(reqMaterial(request), request.sig, g.holder) !== true) return no('holder', 'the request is not signed by the capability holder');
    if (!g.actions.includes(request.action)) return no('scope', 'this capability does not grant ' + request.action);
    const now = ctx.now();
    if (typeof now !== 'number' || !(now < g.expiry)) return no('expiry', 'the capability has expired');
    if (ctx.revoked(g.id) === true) return no('revoked', 'the capability has been revoked');
    const spent = ctx.spent(g.id);
    if (typeof spent !== 'number' || spent < 0 || spent + request.cost > g.budget) return no('budget', 'over budget — ' + (spent + request.cost) + ' of ' + g.budget);
    const last = ctx.lastCounter(g.holder);
    if (typeof last !== 'number' || !(request.counter > last)) return no('replay', 'replay — counter ' + request.counter + ' is not after ' + last);
    return Object.freeze({ admit: true, stage: 'admitted', holder: g.holder, id: g.id, action: request.action, cost: request.cost });
  } catch {
    return no('shape', 'the post failed closed');
  }
}
