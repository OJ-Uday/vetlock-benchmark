/**
 * vetlock scorer — wraps `vetlock diff --json` and normalises to the ScoreResult contract.
 *
 * Uses the installed vetlock CLI (from npm) or a local build (via VETLOCK_CLI env var).
 * If neither is available, `run()` returns { error: '...' } which becomes an `errored` verdict.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { scoreVerdict } from './_scorer-contract.js';

export const scanner = 'vetlock';

/**
 * @returns {Promise<import('./_scorer-contract.js').ScoreResult>}
 */
export async function run({ fixtureDir, manifest }) {
  const beforeLockfile = path.join(fixtureDir, 'lockfile.before.json');
  const afterLockfile = path.join(fixtureDir, 'lockfile.after.json');

  // Resolve which vetlock CLI to invoke.
  // 1. VETLOCK_CLI (absolute path) — for local dev testing an unreleased build.
  // 2. `npx vetlock@0.3.0` — production path. Requires network access unless cached.
  const cliOverride = process.env.VETLOCK_CLI;
  const args = cliOverride
    ? [cliOverride, 'diff', beforeLockfile, afterLockfile, '--json', '--no-progress']
    : ['npx', '--yes', 'vetlock@0.3.0', 'diff', beforeLockfile, afterLockfile, '--json', '--no-progress'];

  const cmd = cliOverride ? 'node' : args.shift();
  const t0 = Date.now();
  const res = spawnSync(cmd, args, {
    encoding: 'utf8',
    timeout: 120_000,
    // Corpus fixtures use relative `file:./` refs in lockfile.after.json.
    // vetlock's fetchOverride resolves those relative to the lockfile's own directory —
    // no extra env needed.
  });
  const durationMs = Date.now() - t0;

  if (res.error) {
    return scoreVerdict({
      fixtureDir, manifest, scanner,
      scannerOutput: { error: `subprocess: ${res.error.message}`, findings: [], durationMs },
    });
  }

  // vetlock's `--json` writes to stdout regardless of exit code (0=CLEAN, 1=WARN, 2=BLOCK, 3=analyzer-error)
  const stdout = res.stdout || '';
  if (!stdout.trim()) {
    return scoreVerdict({
      fixtureDir, manifest, scanner,
      scannerOutput: {
        error: `empty stdout (exit=${res.status}); stderr: ${(res.stderr || '').slice(0, 200)}`,
        findings: [],
        durationMs,
      },
    });
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    return scoreVerdict({
      fixtureDir, manifest, scanner,
      scannerOutput: {
        error: `invalid JSON: ${err.message}; stdout head: ${stdout.slice(0, 200)}`,
        findings: [],
        durationMs,
      },
    });
  }

  return scoreVerdict({
    fixtureDir, manifest, scanner,
    scannerOutput: {
      verdict: parsed.verdict || 'ERROR',
      findings: Array.isArray(parsed.findings) ? parsed.findings : [],
      durationMs,
      scannerVersion: parsed.schemaVersion != null ? `schema-v${parsed.schemaVersion}` : 'unknown',
    },
  });
}
