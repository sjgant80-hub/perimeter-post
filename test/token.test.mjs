import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonical, validGrant, validRequest, capMaterial, reqMaterial, CAP_DOMAIN, REQ_DOMAIN, MAX_ACTIONS, MAX_ACTION_LEN } from '../src/token.mjs';

const grant = { id: 'cap-01', holder: 'a'.repeat(64), actions: ['read', 'write'], budget: 100, expiry: 2000 };
const req = () => ({ capability: { grant, sig: '0'.repeat(128) }, action: 'read', cost: 10, counter: 1, sig: 'f'.repeat(128) });

test('canonical is deterministic and key-order independent', () => {
  assert.equal(canonical({ b: 1, a: 2 }), canonical({ a: 2, b: 1 }));
  assert.equal(canonical([1, 'x', true, null]), '[1,"x",true,null]');
  assert.notEqual(canonical({ a: 1 }), canonical({ a: 2 }));
});

test('validGrant accepts a well-formed grant and rejects each malformation', () => {
  assert.equal(validGrant(grant), true);
  assert.equal(validGrant({ ...grant, id: 'bad id!' }), false);         // id charset
  assert.equal(validGrant({ ...grant, holder: 'zz' }), false);          // not 64 hex
  assert.equal(validGrant({ ...grant, actions: [] }), false);           // empty
  assert.equal(validGrant({ ...grant, actions: ['read', 'read'] }), false); // duplicate
  assert.equal(validGrant({ ...grant, actions: ['Read'] }), false);     // upper-case action
  assert.equal(validGrant({ ...grant, actions: Array.from({ length: MAX_ACTIONS + 1 }, (_, i) => 'a' + i) }), false);
  assert.equal(validGrant({ ...grant, budget: -1 }), false);
  assert.equal(validGrant({ ...grant, budget: 1.5 }), false);
  assert.equal(validGrant({ ...grant, expiry: 'soon' }), false);
  assert.equal(validGrant(null), false);
});

test('validRequest accepts a well-formed request and rejects each malformation', () => {
  assert.equal(validRequest(req()), true);
  assert.equal(validRequest({ ...req(), action: 'Admin' }), false);
  assert.equal(validRequest({ ...req(), cost: -5 }), false);
  assert.equal(validRequest({ ...req(), counter: 2.2 }), false);
  assert.equal(validRequest({ ...req(), sig: 'short' }), false);
  assert.equal(validRequest({ ...req(), capability: { grant, sig: 'xy' } }), false);  // bad cap sig
  assert.equal(validRequest({ ...req(), capability: { grant: { ...grant, budget: -1 }, sig: '0'.repeat(128) } }), false);
  assert.equal(validRequest(null), false);
});

test('capMaterial binds every grant field — change one and the bytes change', () => {
  const m = capMaterial(grant);
  assert.ok(m.startsWith(CAP_DOMAIN));
  for (const k of ['id', 'holder', 'budget', 'expiry']) {
    assert.notEqual(m, capMaterial({ ...grant, [k]: k === 'budget' || k === 'expiry' ? grant[k] + 1 : grant[k] + 'x' }), k);
  }
  assert.notEqual(m, capMaterial({ ...grant, actions: ['read'] }));
});

test('reqMaterial binds the capability id, the action, cost and counter (so a signature cannot be reused across them)', () => {
  const r = req(); const m = reqMaterial(r);
  assert.ok(m.startsWith(REQ_DOMAIN));
  assert.notEqual(m, reqMaterial({ ...r, action: 'write' }));
  assert.notEqual(m, reqMaterial({ ...r, cost: 11 }));
  assert.notEqual(m, reqMaterial({ ...r, counter: 2 }));
  assert.notEqual(m, reqMaterial({ ...r, capability: { grant: { ...grant, id: 'cap-02' }, sig: r.capability.sig } }));
});

test('canonical / validators are total on hostile input', () => {
  for (const x of [null, undefined, 42, 'str', [], {}, { self: {} }]) {
    assert.doesNotThrow(() => canonical(x));
    assert.doesNotThrow(() => validGrant(x));
    assert.doesNotThrow(() => validRequest(x));
    assert.equal(validGrant(x), false);
    assert.equal(validRequest(x), false);
  }
});

test('canonical is total and keeps real serialisation: undefined→null, cycles + toxic getters → markers', () => {
  assert.equal(canonical(undefined), 'null');
  assert.equal(canonical(() => {}), 'null');
  assert.equal(canonical({ b: 1, a: 2 }), '{"a":2,"b":1}');            // real shallow objects unchanged
  const circ = {}; circ.self = circ;
  assert.doesNotThrow(() => canonical(circ));
  assert.match(canonical(circ), /cycle/);
  const toxic = { get x() { throw new Error('no'); } };
  assert.doesNotThrow(() => canonical(toxic));
  assert.match(canonical(toxic), /uncanonical/);
  assert.equal(canonical(10n), '"10"');
});

test('int-field boundaries: 0 and MAX_SAFE_INTEGER are valid, -1 and MAX_SAFE+1 are not', () => {
  const g = { id: 'c', holder: 'a'.repeat(64), actions: ['read'], budget: 0, expiry: 0 };
  assert.equal(validGrant(g), true);                                   // 0 is a valid budget/expiry
  assert.equal(validGrant({ ...g, budget: Number.MAX_SAFE_INTEGER }), true);
  assert.equal(validGrant({ ...g, budget: -1 }), false);
  assert.equal(validGrant({ ...g, budget: Number.MAX_SAFE_INTEGER + 1 }), false);
  assert.equal(validGrant({ ...g, expiry: -1 }), false);
});

test('exactly MAX_ACTIONS is valid; one more is not', () => {
  const g = { id: 'c', holder: 'a'.repeat(64), budget: 1, expiry: 1 };
  assert.equal(validGrant({ ...g, actions: Array.from({ length: MAX_ACTIONS }, (_, i) => 'a' + i) }), true);
  assert.equal(validGrant({ ...g, actions: Array.from({ length: MAX_ACTIONS + 1 }, (_, i) => 'a' + i) }), false);
});

test('a throwing getter makes a grant/request invalid (the catch returns false, never true)', () => {
  const toxicGrant = { get id() { throw new Error('no'); }, holder: 'a'.repeat(64), actions: ['read'], budget: 1, expiry: 1 };
  assert.equal(validGrant(toxicGrant), false);
  const toxicReq = { capability: { get grant() { throw new Error('no'); }, sig: '0'.repeat(128) }, action: 'read', cost: 1, counter: 1, sig: '0'.repeat(128) };
  assert.equal(validRequest(toxicReq), false);
});

test('the request signature must be a 128-hex string: a non-string and a hex-but-wrong-length both fail', () => {
  const r = { capability: { grant: { id: 'c', holder: 'a'.repeat(64), actions: ['read'], budget: 1, expiry: 1 }, sig: '0'.repeat(128) }, action: 'read', cost: 1, counter: 1, sig: 'f'.repeat(128) };
  assert.equal(validRequest(r), true);
  assert.equal(validRequest({ ...r, sig: 123 }), false);              // not a string
  assert.equal(validRequest({ ...r, sig: 'abcd' }), false);          // hex but not 64 bytes
  assert.equal(validRequest({ ...r, capability: { ...r.capability, sig: 456 } }), false);
  assert.equal(validRequest({ ...r, capability: { ...r.capability, sig: 'abcd' } }), false);
});

test('a non-string action is rejected in both the grant list and the request', () => {
  const g = { id: 'c', holder: 'a'.repeat(64), actions: ['read', 123], budget: 1, expiry: 1 };
  assert.equal(validGrant(g), false);                                  // a non-string in the actions list
  const r = { capability: { grant: { ...g, actions: ['read'] }, sig: '0'.repeat(128) }, action: 999, cost: 1, counter: 1, sig: 'f'.repeat(128) };
  assert.equal(validRequest(r), false);                                // a non-string request action
});

test('a non-array actions field is rejected (not just an empty array)', () => {
  assert.equal(validGrant({ id: 'c', holder: 'a'.repeat(64), actions: 'read', budget: 1, expiry: 1 }), false);
  assert.equal(validGrant({ id: 'c', holder: 'a'.repeat(64), actions: 5, budget: 1, expiry: 1 }), false);
});

test('a non-string holder is rejected, and a non-object capability is rejected', () => {
  assert.equal(validGrant({ id: 'c', holder: 123, actions: ['read'], budget: 1, expiry: 1 }), false);
  const base = { action: 'read', cost: 1, counter: 1, sig: 'f'.repeat(128) };
  assert.equal(validRequest({ ...base, capability: null }), false);
  assert.equal(validRequest({ ...base, capability: 42 }), false);
});
