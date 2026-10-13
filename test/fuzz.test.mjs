import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonical, validGrant, validRequest } from '../src/token.mjs';
import { decide } from '../src/post.mjs';

const circular = {}; circular.self = circular;
const toxic = { get id() { throw new Error('toxic'); }, get action() { throw new Error('toxic'); } };
const HOSTILE = [null, undefined, NaN, Infinity, -1, 0, 1, '', '  ', 'str', true, false, 10n, [], {}, circular, toxic, () => {}, Symbol.iterator];
const nt = (name, fn) => test('total: ' + name + ' never throws', () => { for (const x of HOSTILE) assert.doesNotThrow(() => fn(x), name + ' threw on ' + String(x)); });

nt('canonical', canonical);
nt('validGrant', validGrant);
nt('validRequest', validRequest);
const ctx = { operatorKey: 'a'.repeat(64), verify: () => false, now: () => 1000, spent: () => 0, lastCounter: () => 0, revoked: () => false };
test('total: decide never throws and never admits junk', () => {
  for (const x of HOSTILE) { let r; assert.doesNotThrow(() => { r = decide(x, ctx); }); assert.equal(r.admit, false); }
  // and with a hostile ctx
  assert.doesNotThrow(() => decide({}, {}));
  assert.equal(decide({}, {}).admit, false);
});
