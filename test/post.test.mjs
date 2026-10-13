import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verify as edVerify } from 'node:crypto';
import { decide, STAGES } from '../src/post.mjs';
import { capMaterial, reqMaterial } from '../src/token.mjs';
import { keyFromSeed, rawPublic, signWith, publicFromRaw } from '../src/keys.mjs';

const hex = (u8) => Buffer.from(u8).toString('hex');
const OP = keyFromSeed(new Uint8Array(32).fill(1)), AGENT = keyFromSeed(new Uint8Array(32).fill(2)), OTHER = keyFromSeed(new Uint8Array(32).fill(3));
const opPub = hex(rawPublic(OP)), agentPub = hex(rawPublic(AGENT));
const verify = (m, s, p) => { try { return edVerify(null, Buffer.from(m), publicFromRaw(Buffer.from(p, 'hex')), Buffer.from(s, 'hex')) === true; } catch { return false; } };
const grant = { id: 'c1', holder: agentPub, actions: ['read', 'write'], budget: 100, expiry: 2000 };
const issue = (g, signer = OP) => ({ grant: g, sig: hex(signWith(signer)(capMaterial(g))) });
const req = (cap, action, cost, counter, signer = AGENT) => { const r = { capability: cap, action, cost, counter }; return { ...r, sig: hex(signWith(signer)(reqMaterial(r))) }; };
const ctx = (over = {}) => ({ operatorKey: opPub, verify, now: () => 1000, spent: () => 0, lastCounter: () => 0, revoked: () => false, ...over });
const cap = issue(grant);

test('a valid request is admitted, naming the holder, id, action and cost to charge', () => {
  const r = decide(req(cap, 'read', 10, 1), ctx());
  assert.equal(r.admit, true); assert.equal(r.stage, 'admitted');
  assert.equal(r.holder, agentPub); assert.equal(r.id, 'c1'); assert.equal(r.action, 'read'); assert.equal(r.cost, 10);
});

test('each stage is reachable in order', () => {
  assert.equal(decide(null, ctx()).stage, 'shape');
  assert.equal(decide(req(issue(grant, AGENT), 'read', 10, 1), ctx()).stage, 'operator');     // cap not operator-signed
  assert.equal(decide(req(cap, 'read', 10, 1, OTHER), ctx()).stage, 'holder');                 // req not holder-signed
  assert.equal(decide(req(cap, 'admin', 10, 1), ctx()).stage, 'scope');                        // action not granted
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ now: () => 2000 })).stage, 'expiry');     // now >= expiry
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ revoked: () => true })).stage, 'revoked');
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ spent: () => 95 })).stage, 'budget');     // 95+10 > 100
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ lastCounter: () => 1 })).stage, 'replay');
});

test('the budget edge: spent + cost == budget admits, +1 refuses', () => {
  assert.equal(decide(req(cap, 'read', 5, 1), ctx({ spent: () => 95 })).admit, true);          // 95+5 == 100
  assert.equal(decide(req(cap, 'read', 6, 1), ctx({ spent: () => 95 })).stage, 'budget');      // 95+6 == 101
});

test('the expiry edge: now < expiry admits, now == expiry expires', () => {
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ now: () => 1999 })).admit, true);
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ now: () => 2000 })).stage, 'expiry');
});

test('the replay edge: counter == last refuses, counter == last+1 admits', () => {
  assert.equal(decide(req(cap, 'read', 10, 5), ctx({ lastCounter: () => 5 })).stage, 'replay');
  assert.equal(decide(req(cap, 'read', 10, 6), ctx({ lastCounter: () => 5 })).admit, true);
});

test('fails closed when the injected crypto throws, and never admits junk', () => {
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ verify: () => { throw new Error('boom'); } })).admit, false);
  for (const x of [null, undefined, 42, 'x', {}, []]) assert.equal(decide(x, ctx()).admit, false);
});

test('fails closed when the clock, spent, or counter store returns a non-number', () => {
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ now: () => 'soon' })).stage, 'expiry');
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ spent: () => null })).stage, 'budget');
  assert.equal(decide(req(cap, 'read', 10, 1), ctx({ lastCounter: () => undefined })).stage, 'replay');
});

test('STAGES lists the checkpoint order and is frozen', () => {
  assert.deepEqual(STAGES, ['shape', 'operator', 'holder', 'scope', 'expiry', 'revoked', 'budget', 'replay', 'admitted']);
  assert.ok(Object.isFrozen(STAGES));
});
