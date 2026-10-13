// ════════════════════════════════════════════════════════════════
// token.mjs — the capability and the request. Pure, total, gated. Browser-safe (no Buffer); crypto is injected.
//
// A CAPABILITY is a grant the OPERATOR signs: this holder (a public key) may do these ACTIONS, up to this BUDGET,
// until this EXPIRY, under this id (so it can be revoked). A REQUEST is what an agent presents: an action, its
// cost, a fresh counter, and the capability it is acting under — signed by the HOLDER.
//
// Both are signed over a DOMAIN ‖ a CANONICAL serialisation of the exact fields, so neither can be tampered after
// signing (bump the budget, widen the actions, swap the holder) without breaking the signature. The post (post.mjs)
// checks the operator's signature, then the holder's, then scope, expiry, revocation, budget and replay — in that
// order, fail-closed — before it lets the request through.
// ════════════════════════════════════════════════════════════════

export const CAP_DOMAIN = 'PERIMETER-POST/cap/v1\u0000';
export const REQ_DOMAIN = 'PERIMETER-POST/req/v1\u0000';
export const MAX_ACTIONS = 32, MAX_ACTION_LEN = 64, MAX_ID_LEN = 64, MAX_INT = Number.MAX_SAFE_INTEGER;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX = /^(?:[0-9a-f]{2})+$/;
const ID = /^[a-zA-Z0-9_.:-]{1,64}$/;
const ACTION = /^[a-z][a-z0-9_.:-]{0,63}$/;

const isInt = (x) => Number.isInteger(x) && x >= 0 && x <= MAX_INT;
const isStr = (x) => typeof x === 'string';

/** Canonical, deterministic JSON (sorted keys) — the exact bytes a signature covers. Total: a BigInt serialises as
 *  its decimal string, a cycle becomes a fixed marker (a WeakSet, so no stack overflow), and a throwing getter or
 *  any other weirdness falls back to a fixed marker — never a throw. Real grants/requests are shallow and acyclic,
 *  so their serialisation is unaffected. */
export function canonical(v, seen) {
  try {
    if (typeof v === 'bigint') return JSON.stringify(v.toString());
    if (v === null || typeof v !== 'object') { const s = JSON.stringify(v); return s === undefined ? 'null' : s; }
    const s = seen || new WeakSet();
    if (s.has(v)) return '"[cycle]"';
    s.add(v);
    if (Array.isArray(v)) return '[' + v.map((x) => canonical(x, s)).join(',') + ']';
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k], s)).join(',') + '}';
  } catch { return '"[uncanonical]"'; }
}

/** A grant is well-formed: a bounded id, a 32-byte holder key, bounded distinct actions, int budget and expiry.
 *  Total: a hostile object (e.g. a throwing getter) is simply not a valid grant. */
export function validGrant(g) {
  try {
    // one condition per check, so each is reachable on its own (the happy path proves none mis-fires)
    if (!g) return false;
    if (typeof g !== 'object') return false;
    if (Array.isArray(g)) return false;
    if (!isStr(g.id)) return false;
    if (!ID.test(g.id)) return false;
    if (!isStr(g.holder)) return false;
    if (!HEX64.test(g.holder)) return false;
    if (!Array.isArray(g.actions)) return false;
    if (g.actions.length === 0) return false;
    if (g.actions.length > MAX_ACTIONS) return false;
    if (!g.actions.every((a) => isStr(a))) return false;
    if (!g.actions.every((a) => ACTION.test(a))) return false;
    if (new Set(g.actions).size !== g.actions.length) return false;
    if (!isInt(g.budget)) return false;
    if (!isInt(g.expiry)) return false;
    return true;
  } catch { return false; }
}

/** A request is well-formed: a valid embedded capability {grant, sig}, a bounded action, int cost and counter. */
export function validRequest(r) {
  try {
    if (!r) return false;
    if (typeof r !== 'object') return false;
    if (Array.isArray(r)) return false;
    if (!r.capability) return false;
    if (typeof r.capability !== 'object') return false;
    if (!validGrant(r.capability.grant)) return false;
    if (!isStr(r.capability.sig)) return false;
    if (!HEX.test(r.capability.sig)) return false;
    if (r.capability.sig.length !== 128) return false;
    if (!isStr(r.action)) return false;
    if (!ACTION.test(r.action)) return false;
    if (!isInt(r.cost)) return false;
    if (!isInt(r.counter)) return false;
    if (!isStr(r.sig)) return false;
    if (!HEX.test(r.sig)) return false;
    if (r.sig.length !== 128) return false;
    return true;
  } catch { return false; }
}

/** The exact bytes the OPERATOR signs for a grant. */
export function capMaterial(grant) {
  return CAP_DOMAIN + canonical([grant.id, grant.holder, grant.actions, grant.budget, grant.expiry]);
}

/** The exact bytes the HOLDER signs for a request (binds it to the capability id, the action, cost and counter). */
export function reqMaterial(req) {
  return REQ_DOMAIN + canonical([req.capability.grant.id, req.action, req.cost, req.counter]);
}
