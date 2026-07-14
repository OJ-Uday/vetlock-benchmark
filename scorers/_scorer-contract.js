/**
 * Scorer contract — every scanner adapter under scorers/ implements this shape.
 *
 * Input: a fixture directory with lockfile.before.json + lockfile.after.json + manifest.json
 * Output: a canonical Verdict object
 *
 * Verdicts:
 *   caught  — scanner returned non-CLEAN AND at least one finding on the correct package
 *   partial — non-CLEAN but findings on the wrong package
 *   missed  — CLEAN or non-CLEAN on unrelated packages
 *   errored — unhandled crash (graceful "unsupported format" = missed, not errored)
 *
 * A scorer MUST fully wrap the scanner subprocess — including timeouts, error handling, and
 * signal propagation. If a scorer itself throws, run-benchmark.js records `errored` on the
 * scanner's behalf.
 */

/** @typedef {'caught' | 'partial' | 'missed' | 'errored'} Verdict */

/** @typedef {{
 *   verdict: Verdict,
 *   scanner: string,
 *   scannerVersion?: string,
 *   fixtureId: string,
 *   findingCount: number,
 *   findingsPreview: string[],
 *   durationMs: number,
 *   error?: string
 * }} ScoreResult */

/** @typedef {{
 *   id: string,
 *   ecosystem: 'npm' | 'pypi' | 'golang' | 'crates' | 'gems' | 'maven',
 *   package: string,
 *   affectedVersions: string[],
 *   expectedCaughtBy?: Record<string, boolean>
 * }} FixtureManifest */

/**
 * Extract the affected package name from a fixture manifest. The vetlock corpus
 * uses `.packages.malicious.name` (older shape); newer benchmark-native fixtures
 * use a flat `.package` field. Handle both.
 */
export function affectedPackage(manifest) {
  if (typeof manifest.package === 'string') return manifest.package;
  if (manifest.packages?.malicious?.name) return manifest.packages.malicious.name;
  return null;
}

/**
 * Score a scanner's output against a fixture.
 *
 * @param {object} args
 * @param {string} args.fixtureDir              Absolute path to corpus/<id>/
 * @param {FixtureManifest} args.manifest       Parsed manifest.json
 * @param {{
 *   verdict: 'CLEAN' | 'INFO' | 'WARN' | 'BLOCK' | 'ERROR',
 *   findings: Array<{ package?: string; detector?: string; message?: string }>,
 *   error?: string,
 *   durationMs: number,
 *   scannerVersion?: string
 * }} args.scannerOutput                        Normalised output from the scorer's `run()` call
 * @param {string} args.scanner                 Scanner name (e.g. 'vetlock')
 * @returns {ScoreResult}
 */
export function scoreVerdict({ fixtureDir, manifest, scannerOutput, scanner }) {
  if (scannerOutput.error) {
    return {
      verdict: 'errored',
      scanner,
      scannerVersion: scannerOutput.scannerVersion,
      fixtureId: manifest.id,
      findingCount: 0,
      findingsPreview: [],
      durationMs: scannerOutput.durationMs,
      error: scannerOutput.error,
    };
  }

  const findings = Array.isArray(scannerOutput.findings) ? scannerOutput.findings : [];
  const affected = affectedPackage(manifest);
  const onCorrectPackage = findings.filter(
    (f) => f.package && affected && f.package === affected,
  );
  const onWrongPackage = findings.filter(
    (f) => f.package && affected && f.package !== affected,
  );

  let verdict;
  if (scannerOutput.verdict === 'CLEAN') {
    verdict = 'missed';
  } else if (onCorrectPackage.length > 0) {
    verdict = 'caught';
  } else if (onWrongPackage.length > 0) {
    verdict = 'partial';
  } else {
    // Scanner said non-CLEAN but produced no findings we can attribute — treat as missed
    verdict = 'missed';
  }

  return {
    verdict,
    scanner,
    scannerVersion: scannerOutput.scannerVersion,
    fixtureId: manifest.id,
    findingCount: findings.length,
    findingsPreview: findings.slice(0, 5).map((f) => {
      const pkg = f.package || '(no pkg)';
      const det = f.detector || '(no detector)';
      return `${pkg} · ${det}`;
    }),
    durationMs: scannerOutput.durationMs,
  };
}
