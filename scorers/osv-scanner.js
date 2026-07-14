/**
 * OSV-Scanner scorer — wraps `osv-scanner` and normalises to the ScoreResult contract.
 *
 * OSV-Scanner reads lockfiles and reports known CVEs / GHSAs against the OSV database.
 * Its detection model is fundamentally different from vetlock's (advisory-DB match, not
 * behavioral diff), so this scorer is included to make that difference visible on the
 * scoreboard: OSV-Scanner catches attacks that have been assigned CVEs; it does NOT catch
 * novel behavior changes.
 *
 * Install: `go install github.com/google/osv-scanner/cmd/osv-scanner@latest`
 * Or via prebuilt binary — see https://github.com/google/osv-scanner
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { scoreVerdict } from './_scorer-contract.js';

export const scanner = 'osv-scanner';

/**
 * @returns {Promise<import('./_scorer-contract.js').ScoreResult>}
 */
export async function run({ fixtureDir, manifest }) {
  // OSV-Scanner takes ONE lockfile (it doesn't diff). We give it the AFTER lockfile
  // and it reports advisories against every version in it.
  const afterLockfile = path.join(fixtureDir, 'lockfile.after.json');

  const t0 = Date.now();
  const res = spawnSync('osv-scanner', ['--format', 'json', '--lockfile', afterLockfile], {
    encoding: 'utf8',
    timeout: 60_000,
  });
  const durationMs = Date.now() - t0;

  if (res.error) {
    // Most common cause: osv-scanner not installed. That's a real environmental error,
    // not the scanner's fault — but per the honesty rules, missing scanner => scorer
    // records the error and the fixture is `errored` for that scanner.
    return scoreVerdict({
      fixtureDir, manifest, scanner,
      scannerOutput: { error: `subprocess: ${res.error.message}`, findings: [], durationMs },
    });
  }

  const stdout = res.stdout || '';
  if (!stdout.trim()) {
    // OSV-Scanner exits 0 with empty output when there are no vulnerabilities.
    return scoreVerdict({
      fixtureDir, manifest, scanner,
      scannerOutput: { verdict: 'CLEAN', findings: [], durationMs, scannerVersion: 'unknown' },
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
        findings: [], durationMs,
      },
    });
  }

  // Flatten OSV-Scanner's nested vulns[] shape into our finding form: one finding per
  // matched advisory, keyed by package name.
  const findings = [];
  for (const result of parsed.results || []) {
    for (const pkg of result.packages || []) {
      const pkgName = pkg.package?.name;
      for (const vuln of pkg.vulnerabilities || []) {
        findings.push({
          package: pkgName,
          detector: `osv.${vuln.id || 'unknown'}`,
          message: vuln.summary || vuln.details?.slice?.(0, 120) || vuln.id,
        });
      }
    }
  }

  return scoreVerdict({
    fixtureDir, manifest, scanner,
    scannerOutput: {
      verdict: findings.length > 0 ? 'BLOCK' : 'CLEAN',
      findings,
      durationMs,
      scannerVersion: 'osv-scanner',
    },
  });
}
