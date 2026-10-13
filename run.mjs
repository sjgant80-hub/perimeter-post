#!/usr/bin/env node
// run.mjs — stand the perimeter post up and walk an agent through it.
//   node run.mjs
// The OPERATOR issues a capability to an AGENT (may read/write, budget 100, expiring soon). The agent makes
// requests; the post admits what the grant covers and refuses everything else — a forged grant, a stolen one, an
// over-scope action, an expired one, a replay, over budget. In-process, so the whole walk prints at once.
import { decide } from './src/post.mjs';
import { capMaterial, reqMaterial } from './src/token.mjs';
import { keyFromSeed, rawPublic, signWith, publicFromRaw } from './src/keys.mjs';
import { verify as edVerify } from 'node:crypto';

const hex = (u8) => Buffer.from(u8).toString('hex');
const OPERATOR = keyFromSeed(new Uint8Array(32).fill(1)), AGENT = keyFromSeed(new Uint8Array(32).fill(2)), THIEF = keyFromSeed(new Uint8Array(32).fill(3));
const verify = (m, s, p) => { try { return edVerify(null, Buffer.from(m), publicFromRaw(Buffer.from(p, 'hex')), Buffer.from(s, 'hex')) === true; } catch { return false; } };
const issue = (g, signer = OPERATOR) => ({ grant: g, sig: hex(signWith(signer)(capMaterial(g))) });
const req = (cap, action, cost, counter, signer = AGENT) => { const r = { capability: cap, action, cost, counter }; return { ...r, sig: hex(signWith(signer)(reqMaterial(r))) }; };

// the operator's revocation list, the spend ledger, and each holder's last counter — the post's live state
const revoked = new Set(), spent = new Map(), last = new Map();
const ctx = (now) => ({ operatorKey: hex(rawPublic(OPERATOR)), verify, now: () => now,
  spent: (id) => spent.get(id) || 0, lastCounter: (h) => last.get(h) || 0, revoked: (id) => revoked.has(id) });
function present(label, request, now = 1000) {
  const r = decide(request, ctx(now));
  if (r.admit) { spent.set(r.id, (spent.get(r.id) || 0) + r.cost); last.set(r.holder, request.counter); console.log(`  ADMIT   ${label.padEnd(44)} (charged ${r.cost}; spent ${spent.get(r.id)})`); }
  else console.log(`  refuse  ${label.padEnd(44)} → ${r.stage}: ${r.reason}`);
}

console.log('\nPERIMETER POST — the checkpoint in front of kar-hub\n');
const grant = { id: 'cap-01', holder: hex(rawPublic(AGENT)), actions: ['read', 'write'], budget: 100, expiry: 2000 };
const cap = issue(grant);
console.log('the operator issued cap-01 to the agent: may read/write, budget 100, expires at 2000.\n');

present('read, cost 10, counter 1', req(cap, 'read', 10, 1));
present('write, cost 30, counter 2', req(cap, 'write', 30, 2));
present('admin, cost 10, counter 3 (not in grant)', req(cap, 'admin', 10, 3));
present('read, cost 10, counter 2 (replay)', req(cap, 'read', 10, 2));
present('read, cost 70, counter 3 (over budget: 40+70>100)', req(cap, 'read', 70, 3));
present('a grant the AGENT signed itself (forged)', req(issue(grant, AGENT), 'read', 10, 3));
present('a request the THIEF signed (stolen cap)', req(cap, 'read', 10, 3, THIEF));
present('read, cost 10, counter 3 — after expiry', req(cap, 'read', 10, 3), 2000);
revoked.add('cap-01');
present('read, cost 10, counter 3 — after revocation', req(cap, 'read', 10, 3));

console.log('\nproof of every intrusion: node attack-kit/redteam.mjs --check\n');
