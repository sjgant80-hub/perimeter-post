#!/usr/bin/env node
// attack-kit/redteam.mjs — simulated intrusion attempts against the post. A valid agent gets in within its grant;
// every forgery, over-reach, replay and tamper is refused.
//   node attack-kit/redteam.mjs           write receipts/redteam.json
//   node attack-kit/redteam.mjs --check   regenerate and demand it is byte-identical
// Deterministic keys + a fixed clock → reproducible. A case HOLDS when it lands at the stage it should.
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { verify as edVerify } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../src/post.mjs';
import { capMaterial, reqMaterial } from '../src/token.mjs';
import { keyFromSeed, rawPublic, signWith, publicFromRaw } from '../src/keys.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'receipts', 'redteam.json');
const hex = (u8) => Buffer.from(u8).toString('hex');
const seed = (b) => keyFromSeed(new Uint8Array(32).fill(b));

const OPERATOR = seed(1), AGENT = seed(2), THIEF = seed(3), ROGUE_OP = seed(9);
const opPub = hex(rawPublic(OPERATOR)), agentPub = hex(rawPublic(AGENT));
const NOW = 1000;                                   // fixed clock for the receipt
const verify = (msg, sig, pubHex) => { try { return edVerify(null, Buffer.from(msg), publicFromRaw(Buffer.from(pubHex, 'hex')), Buffer.from(sig, 'hex')) === true; } catch { return false; } };

// issue a capability (the operator signs the grant) — optionally with the wrong signer, or tamper AFTER signing
const issue = (grant, signer = OPERATOR, tamper) => { const sig = hex(signWith(signer)(capMaterial(grant))); const g = tamper ? tamper({ ...grant }) : grant; return { grant: g, sig }; };
// make a request (the holder signs it) — optionally wrong signer
const request = (capability, action, cost, counter, signer = AGENT) => { const r = { capability, action, cost, counter }; return { ...r, sig: hex(signWith(signer)(reqMaterial(r))) }; };

const grant = { id: 'cap-01', holder: agentPub, actions: ['read', 'write'], budget: 100, expiry: 2000 };
const cap = issue(grant);
const base = (over = {}) => ({ operatorKey: opPub, verify, now: () => NOW, spent: () => 0, lastCounter: () => 0, revoked: () => false, ...over });

const cases = [];
const add = (name, tried, got, ok) => cases.push({ name, tried, got, held: ok === true });
const stage = (r) => r.admit ? 'ADMITTED' : r.stage;

// ── the valid agent gets in, within its grant ───────────────────────────────────────────────────────────────
add('a valid request inside the grant is admitted', 'read, cost 10, counter 1', stage(decide(request(cap, 'read', 10, 1), base())), decide(request(cap, 'read', 10, 1), base()).admit === true);
add('a second valid request (fresh counter, in budget) is admitted', 'write, cost 10, counter 2, 10 already spent', stage(decide(request(cap, 'write', 10, 2), base({ spent: () => 10, lastCounter: () => 1 }))), decide(request(cap, 'write', 10, 2), base({ spent: () => 10, lastCounter: () => 1 })).admit === true);

// ── intrusions ───────────────────────────────────────────────────────────────────────────────────────────────
add('a capability NOT signed by the operator', 'the agent signs its own grant', stage(decide(request(issue(grant, AGENT), 'read', 10, 1), base())), stage(decide(request(issue(grant, AGENT), 'read', 10, 1), base())) === 'operator');
add('a capability signed by a DIFFERENT (rogue) operator', 'rogue key, not the pinned one', stage(decide(request(issue(grant, ROGUE_OP), 'read', 10, 1), base())), stage(decide(request(issue(grant, ROGUE_OP), 'read', 10, 1), base())) === 'operator');
add('the grant tampered after signing (budget bumped)', 'operator signs budget 100, attacker sets 10^9', stage(decide(request(issue(grant, OPERATOR, (g) => { g.budget = 1000000000; return g; }), 'read', 10, 1), base())), stage(decide(request(issue(grant, OPERATOR, (g) => { g.budget = 1000000000; return g; }), 'read', 10, 1), base())) === 'operator');
add('the grant tampered after signing (actions widened)', 'operator grants [read,write], attacker adds admin', stage(decide(request(issue(grant, OPERATOR, (g) => { g.actions = [...g.actions, 'admin']; return g; }), 'admin', 10, 1), base())), stage(decide(request(issue(grant, OPERATOR, (g) => { g.actions = [...g.actions, 'admin']; return g; }), 'admin', 10, 1), base())) === 'operator');
add('the request NOT signed by the holder', 'a thief signs a request under the agent\'s capability', stage(decide(request(cap, 'read', 10, 1, THIEF), base())), stage(decide(request(cap, 'read', 10, 1, THIEF), base())) === 'holder');
add('an action the capability does not grant (over-scope)', 'admin, which is not in [read,write]', stage(decide(request(cap, 'admin', 10, 1), base())), stage(decide(request(cap, 'admin', 10, 1), base())) === 'scope');
add('an expired capability', 'now 2000 ≥ expiry 2000', stage(decide(request(cap, 'read', 10, 1), base({ now: () => 2000 }))), stage(decide(request(cap, 'read', 10, 1), base({ now: () => 2000 }))) === 'expiry');
add('a revoked capability', 'the operator revoked cap-01', stage(decide(request(cap, 'read', 10, 1), base({ revoked: () => true }))), stage(decide(request(cap, 'read', 10, 1), base({ revoked: () => true }))) === 'revoked');
add('over budget', 'cost 10 but 95 of 100 already spent', stage(decide(request(cap, 'read', 10, 1), base({ spent: () => 95 }))), stage(decide(request(cap, 'read', 10, 1), base({ spent: () => 95 }))) === 'budget');
add('exactly the budget edge is allowed', 'cost 5 with 95 spent (=100)', stage(decide(request(cap, 'read', 5, 1), base({ spent: () => 95 }))), decide(request(cap, 'read', 5, 1), base({ spent: () => 95 })).admit === true);
add('a replayed request (counter not advanced)', 'counter 1 when last is already 1', stage(decide(request(cap, 'read', 10, 1), base({ lastCounter: () => 1 }))), stage(decide(request(cap, 'read', 10, 1), base({ lastCounter: () => 1 }))) === 'replay');
add('a request replayed under a DIFFERENT capability id cannot reuse its signature', 'reqMaterial binds the cap id', (() => { const r = request(cap, 'read', 10, 5); const other = { ...r, capability: issue({ ...grant, id: 'cap-02' }) }; return stage(decide(other, base())); })(), (() => { const r = request(cap, 'read', 10, 5); const other = { ...r, capability: issue({ ...grant, id: 'cap-02' }) }; return stage(decide(other, base())); })() === 'holder');
add('a malformed request is refused at shape, never a throw', 'null', stage(decide(null, base())), stage(decide(null, base())) === 'shape');

const held = cases.every((c) => c.held);
const result = { kind: 'perimeter-post-redteam', v: 1, rule: 'a valid agent gets in within its grant; every forgery, over-reach, replay and tamper is refused', cases: cases.length, held, results: cases };
const canonical = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v) : Array.isArray(v) ? '[' + v.map(canonical).join(',') + ']' : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
const text = canonical(result) + '\n';
if (process.argv.includes('--check')) {
  const committed = existsSync(OUT) ? readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') : '';
  if (committed !== text) { console.error('the receipt does NOT reproduce'); process.exit(1); }
  console.log('REPRODUCED — ' + result.cases + ' cases, all held: ' + result.held); process.exit(result.held ? 0 : 1);
}
mkdirSync(dirname(OUT), { recursive: true }); writeFileSync(OUT, text);
for (const c of cases) console.log((c.held ? 'HELD  ' : 'BROKE ') + c.name.slice(0, 62).padEnd(64) + ' → ' + c.got);
console.log('\n' + (held ? 'the post holds' : 'A CASE BROKE') + ' — ' + cases.length + ' cases → receipts/redteam.json');
process.exit(held ? 0 : 1);
