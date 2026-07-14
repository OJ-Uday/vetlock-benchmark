# vetlock-benchmark

> **A public, versioned, defanged benchmark for npm supply-chain scanners.**
> Score any scanner against a shared corpus of real historical attacks — measurable, reproducible, honest.

**Version**: 0.1 (draft, iterating before public invitation to competitors) · **License**: Apache-2.0 (scorers), CC0-1.0 (corpus + rules)

---

## Why this exists

Every scanner (Snyk, Socket, npm-audit, OSV-Scanner, vetlock) claims to catch supply-chain attacks. Nobody can compare them apples-to-apples because:

1. **No shared corpus.** Each vendor tests against their own set.
2. **No shared scoring rules.** "Detected" means different things across tools.
3. **No shared vocabulary for how attacks work.** Fixed by [OSIF](https://github.com/OJ-Uday/osif-spec).
4. **No public scoreboard.** Trust me bro is the alternative.

`vetlock-benchmark` fixes all four:

- **Corpus:** every attack ships as a defanged fixture (see `corpus/`) with a companion OSIF document that describes its mechanics in a machine-readable, tool-neutral way.
- **Scoring harness:** run any scanner against every fixture, extract its verdict (`caught` / `missed` / `errored`), publish a scorecard.
- **Scoreboard:** [`docs/SCOREBOARD.md`](docs/SCOREBOARD.md) — regenerated from `results/*.json` on every merge.
- **Submission path:** anyone can PR a new attack fixture. The `defang-guard` CI check enforces no live IOCs.

## Honesty rules (non-negotiable)

- **vetlock is scored by the same harness as everyone else.** vetlock's misses are published on the scoreboard.
- **External attack submissions are accepted.** If your scanner catches something vetlock doesn't, submit the fixture. Your PR gets merged, vetlock's score drops, we work on closing the gap.
- **Every URL/domain indicator in every fixture is defanged** (RFC-2606 reserved TLDs: `.invalid`, `.example`, `.test`, `.localhost`, or `hxxp`/`[.]`/`(.)` defang notations). Enforced by `scripts/defang-guard.js`.
- **The benchmark version is a git tag.** Scoring is meaningful only against a specific corpus version. `v0.1` is what the current scoreboard reflects.

## Getting started

### Run the benchmark against vetlock

```bash
# Prerequisite: npx (Node 20+) — vetlock installs via npx at run time
node scripts/run-benchmark.js --scanner vetlock

# Output: results/vetlock-YYYY-MM-DD.json
# Also regenerates docs/SCOREBOARD.md
```

### Run against another scanner

```bash
# Each scorer under scorers/ implements the same interface: input = fixture dir,
# output = JSON verdict. Add your own scorer by dropping a file in scorers/.
node scripts/run-benchmark.js --scanner osv-scanner
node scripts/run-benchmark.js --scanner npm-audit
```

### Submit a new attack fixture

```
corpus/<attack-id>/
  manifest.json          — id, ecosystem, package, versions, expected findings (per-scanner if desired)
  incident.osif.json     — OSIF document describing the attack's mechanics
  lockfile.before.json   — pre-attack lockfile
  lockfile.after.json    — post-attack lockfile
  <pkg>-<v>/…            — tarball artifacts (DEFANGED — no live URLs, no working payloads)
  README.md              — human-readable narrative
```

`scripts/defang-guard.js` rejects any fixture containing a live-looking URL, a working payload marker, or an SRI hash matching a known-malicious tarball published elsewhere.

## What "caught" means (the scoring rules)

A scanner is scored on **each attack** with one of four verdicts:

| Verdict     | Rule |
|-------------|------|
| `caught`    | Scanner returns a non-CLEAN verdict AND at least one finding is on the correct package/version |
| `partial`   | Scanner returns non-CLEAN but findings are on the wrong package (adjacency false-positive that happens to intersect the attack) |
| `missed`    | Scanner returns CLEAN, OR returns non-CLEAN but on a completely unrelated package |
| `errored`   | Scanner exits with an unhandled crash (never a graceful "unsupported format" — that counts as `missed`) |

Aggregate score: `caught / (caught + partial + missed + errored)`. Errors count against you; graceful "unsupported" would not. Every scanner is scored on every attack; N/A is not a valid verdict.

## Roadmap

- **v0.1** (current): npm-only corpus (13 fixtures inherited from vetlock's replay set). vetlock + OSV-Scanner scored.
- **v0.2**: pnpm-lock + yarn-lock fixtures. Snyk + npm-audit scored (invitation-based; we'll run their free tier and publish).
- **v0.3**: PyPI ecosystem (via vetlock P4c). Python fixtures ship with OSIF docs.
- **v1.0**: stable corpus format, invitation to hand governance to a neutral home (OpenSSF or similar). Coincides with vetlock v1.0 launch.

## License

Scorers (`scorers/*.js`): Apache-2.0.
Corpus fixtures + scoring rules: **CC0-1.0** — public domain equivalent, usable by any tool including competitors.

## Related repos

- [`OJ-Uday/vetlock`](https://github.com/OJ-Uday/vetlock) — the scanner this benchmark was born from
- [`OJ-Uday/osif-spec`](https://github.com/OJ-Uday/osif-spec) — the vocabulary each fixture ships with
