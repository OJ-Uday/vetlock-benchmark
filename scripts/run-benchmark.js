#!/usr/bin/env node
/**
 * run-benchmark.js — score a scanner against every corpus fixture.
 *
 * Usage:
 *   node scripts/run-benchmark.js --scanner vetlock
 *   node scripts/run-benchmark.js --scanner osv-scanner --output results/osv-scanner-2026-07-14.json
 *   node scripts/run-benchmark.js --scanner all       (runs every scorer under scorers/)
 *
 * Output:
 *   results/<scanner>-<YYYY-MM-DD>.json  (structured)
 *   docs/SCOREBOARD.md                   (regenerated from ALL results/*.json)
 *
 * Honesty rules:
 *   - Every scanner is run against every fixture. No skipping.
 *   - If a scanner is missing (e.g. osv-scanner not installed), all its fixtures
 *     record `errored`, not `skipped`. That is the honest verdict.
 *   - The scoreboard shows caught/partial/missed/errored counts per scanner.
 *     No scanner can be excluded because "the environment wasn't right."
 */

import { readdirSync, readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..');
const CORPUS_DIR = path.join(REPO_ROOT, 'corpus');
const SCORERS_DIR = path.join(REPO_ROOT, 'scorers');
const RESULTS_DIR = path.join(REPO_ROOT, 'results');

// ── CLI parse ─────────────────────────────────────────────
const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  const k = process.argv[i];
  const v = process.argv[i + 1];
  if (k && k.startsWith('--')) args.set(k.slice(2), v);
}
const target = args.get('scanner') || 'all';

// ── Load fixtures ─────────────────────────────────────────
function loadFixtures() {
  if (!existsSync(CORPUS_DIR)) {
    console.error(`no corpus at ${CORPUS_DIR}`);
    process.exit(2);
  }
  const fixtures = [];
  for (const entry of readdirSync(CORPUS_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('_') || entry.name.startsWith('.')) continue;
    const manifestPath = path.join(CORPUS_DIR, entry.name, 'manifest.json');
    if (!existsSync(manifestPath)) continue;
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    } catch {
      console.error(`  skipping ${entry.name}: manifest.json invalid`);
      continue;
    }
    fixtures.push({
      dir: path.join(CORPUS_DIR, entry.name),
      manifest,
    });
  }
  return fixtures.sort((a, b) => a.manifest.id.localeCompare(b.manifest.id));
}

// ── Load scorers ──────────────────────────────────────────
async function loadScorers() {
  const scorers = {};
  if (!existsSync(SCORERS_DIR)) return scorers;
  for (const entry of readdirSync(SCORERS_DIR)) {
    if (!entry.endsWith('.js') || entry.startsWith('_')) continue;
    const modUrl = pathToFileURL(path.join(SCORERS_DIR, entry)).href;
    const mod = await import(modUrl);
    if (!mod.scanner || typeof mod.run !== 'function') continue;
    scorers[mod.scanner] = mod;
  }
  return scorers;
}

// ── Run one scanner against every fixture ────────────────
async function runOneScanner(scorer, fixtures) {
  const results = [];
  console.log(`\n== ${scorer.scanner} ==`);
  for (const fx of fixtures) {
    let result;
    try {
      result = await scorer.run({ fixtureDir: fx.dir, manifest: fx.manifest });
    } catch (err) {
      result = {
        verdict: 'errored',
        scanner: scorer.scanner,
        fixtureId: fx.manifest.id,
        findingCount: 0,
        findingsPreview: [],
        durationMs: 0,
        error: err.message,
      };
    }
    const glyph = {
      caught: '✓', partial: '⚠', missed: '✗', errored: '!',
    }[result.verdict] || '?';
    console.log(`  ${glyph}  ${fx.manifest.id.padEnd(32)} ${result.verdict.padEnd(8)} (${result.findingCount} findings, ${result.durationMs}ms)`);
    if (result.error) console.log(`      error: ${result.error.slice(0, 120)}`);
    results.push(result);
  }
  return results;
}

// ── Persist + summarise ──────────────────────────────────
function summarise(results) {
  const counts = { caught: 0, partial: 0, missed: 0, errored: 0 };
  for (const r of results) counts[r.verdict]++;
  const total = results.length;
  const score = total > 0 ? (counts.caught / total) : 0;
  return { total, counts, score };
}

function writeResults(scannerName, results) {
  const today = new Date().toISOString().slice(0, 10);
  const outPath = path.join(RESULTS_DIR, `${scannerName}-${today}.json`);
  mkdirSync(RESULTS_DIR, { recursive: true });
  const summary = summarise(results);
  writeFileSync(outPath, JSON.stringify({
    scanner: scannerName,
    date: today,
    summary,
    results,
  }, null, 2));
  console.log(`\n  → ${path.relative(REPO_ROOT, outPath)}`);
  console.log(`  summary: caught=${summary.counts.caught} partial=${summary.counts.partial} missed=${summary.counts.missed} errored=${summary.counts.errored}  score=${(summary.score * 100).toFixed(1)}%`);
}

// ── Main ─────────────────────────────────────────────────
(async () => {
  const fixtures = loadFixtures();
  if (fixtures.length === 0) {
    console.error('no fixtures found under corpus/');
    process.exit(2);
  }
  console.log(`loaded ${fixtures.length} fixture(s)`);

  const allScorers = await loadScorers();
  if (Object.keys(allScorers).length === 0) {
    console.error('no scorers found under scorers/');
    process.exit(2);
  }

  const targets = target === 'all' ? Object.values(allScorers) : [allScorers[target]];
  if (!targets[0]) {
    console.error(`unknown scanner: ${target}. available: ${Object.keys(allScorers).join(', ')}`);
    process.exit(2);
  }

  for (const scorer of targets) {
    const results = await runOneScanner(scorer, fixtures);
    writeResults(scorer.scanner, results);
  }

  console.log('\ndone');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
