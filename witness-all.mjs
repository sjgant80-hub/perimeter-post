#!/usr/bin/env node
// witness-all.mjs — the re-runnable mutation + fuzz gate over the perimeter post's decision kernels.
//   token — the capability/request wire + validators + the signed materials (what binds a signature)
//   post  — THE CHECKPOINT: operator → holder → scope → expiry → revoked → budget → replay, fail-closed
// keys.mjs (node:crypto glue) is not gated; it is exercised by every test that signs. Reviewed-equivalent
// survivors, with a written reason each, live in witness.baseline.json.
import { runMutations } from './.witness/witness.mjs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const HERE = dirname(fileURLToPath(import.meta.url));
export const PAIRS = [
  ['src/token.mjs', ['test/token.test.mjs', 'test/fuzz.test.mjs']],
  ['src/post.mjs', ['test/post.test.mjs', 'test/fuzz.test.mjs']],
];
const only = process.argv.slice(2);
let allClean = true; const rows = [];
for (const [src, tests] of PAIRS) {
  if (only.length && !only.includes(src)) continue;
  const testFiles = Array.isArray(tests) ? tests : [tests];
  const t0 = Date.now();
  const r = runMutations(join(HERE, src), { cwd: HERE, cap: 5000, timeout: 60000, testCmd: ['node', '--test', ...testFiles] });
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  rows.push({ src, killed: r.killed, total: r.total, survived: r.survived.length, ignored: r.ignored.length, capped: r.capped });
  console.log(`${r.clean && !r.capped ? '✓' : '✗'} ${src.padEnd(14)} ${String(r.killed).padStart(3)}/${String(r.total).padEnd(3)} killed${r.ignored.length ? ` · ${r.ignored.length} reviewed-equivalent` : ''}${r.capped ? ' · CAPPED' : ''} · ${secs}s`);
  for (const s of r.survived) console.log(`    SURVIVED line ${s.line}: ${s.mutation} :: ${s.snippet}`);
  if (!r.clean || r.capped) allClean = false;
}
const k = rows.reduce((a, r) => a + r.killed, 0), n = rows.reduce((a, r) => a + r.total, 0);
console.log(`\n${allClean ? 'WITNESS CLEAN' : 'WITNESS NOT CLEAN'} — ${k}/${n} mutants killed`);
process.exit(allClean ? 0 : 1);
