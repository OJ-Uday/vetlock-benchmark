/**
 * npm-audit scorer — wraps `npm audit --json` and normalises to the ScoreResult contract.
 *
 * npm-audit is Node's built-in advisory scanner. It reads package-lock.json and
 * reports advisories against packages present in the tree.  Like OSV-Scanner, it's
 * advisory-DB-based (matches known CVEs/GHSAs); it does NOT catch novel behavior.
 *
 * `npm audit --json` requires actually running an install first — annoying and slow.
 * We work around this by creating a temp dir with the lockfile and doing `npm audit
 * --package-lock-only` so no install is needed.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scoreVerdict } from './_scorer-contract.js';

export const scanner = 'npm-audit';

/**
 * @returns {Promise<import('./_scorer-contract.js').ScoreResult>}
 */
export async function run({ fixtureDir, manifest }) {
  const afterLockfilePath = path.join(fixtureDir, 'lockfile.after.json');
  let afterLockfile;
  try {
    afterLockfile = readFileSync(afterLockfilePath, 'utf8');
  } catch (err) {
    return scoreVerdict({
      fixtureDir, manifest, scanner,
      scannerOutput: { error: `read lockfile: ${err.message}`, findings: [], durationMs: 0 },
    });
  }

  const workdir = mkdtempSync(path.join(os.tmpdir(), 'npm-audit-scorer-'));
  const t0 = Date.now();
  try {
    writeFileSync(path.join(workdir, 'package-lock.json'), afterLockfile);
    // Minimal package.json — npm audit reads name/version.
    writeFileSync(path.join(workdir, 'package.json'), JSON.stringify({
      name: manifest.id, version: '0.0.0', private: true,
    }, null, 2));

    const res = spawnSync('npm', ['audit', '--json', '--package-lock-only'], {
      cwd: workdir, encoding: 'utf8', timeout: 60_000,
    });
    const durationMs = Date.now() - t0;

    if (res.error) {
      return scoreVerdict({
        fixtureDir, manifest, scanner,
        scannerOutput: { error: `subprocess: ${res.error.message}`, findings: [], durationMs },
      });
    }

    const stdout = res.stdout || '';
    if (!stdout.trim()) {
      return scoreVerdict({
        fixtureDir, manifest, scanner,
        scannerOutput: { verdict: 'CLEAN', findings: [], durationMs, scannerVersion: 'npm-audit' },
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

    // npm audit's shape: { vulnerabilities: { <pkg>: { name, severity, via: [...] } } }
    const vulns = parsed.vulnerabilities || {};
    const findings = [];
    for (const [pkgName, vuln] of Object.entries(vulns)) {
      const via = Array.isArray(vuln.via) ? vuln.via : [];
      for (const src of via) {
        if (typeof src === 'string') {
          findings.push({ package: pkgName, detector: `npm-audit.${src}`, message: `${vuln.severity} via ${src}` });
        } else if (src && typeof src === 'object') {
          findings.push({
            package: pkgName,
            detector: `npm-audit.${src.source || 'advisory'}`,
            message: src.title || `${vuln.severity} vulnerability`,
          });
        }
      }
    }

    return scoreVerdict({
      fixtureDir, manifest, scanner,
      scannerOutput: {
        verdict: findings.length > 0 ? 'BLOCK' : 'CLEAN',
        findings, durationMs,
        scannerVersion: 'npm-audit',
      },
    });
  } finally {
    try { rmSync(workdir, { recursive: true, force: true }); } catch {}
  }
}
