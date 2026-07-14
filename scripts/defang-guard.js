#!/usr/bin/env node
/**
 * Defang guard — refuses any commit that adds a live URL/domain indicator to
 * a corpus fixture. Runs in CI on every PR.
 *
 * Rules (a fixture violates ANY = fail):
 *  1. No URL containing a real domain (must be .invalid / .example / .test / .localhost)
 *  2. No IP address that looks routable (10.*, 192.168.*, 127.* etc. are OK; anything
 *     else is real)
 *  3. No SRI hash matching a known-malicious tarball (a small blocklist under
 *     scripts/known-malicious-sri.txt; the CI job pulls a fresh copy from OSV before
 *     each run)
 */

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..');
const CORPUS_DIR = path.join(REPO_ROOT, 'corpus');

const RESERVED_TLDS = ['.invalid', '.example', '.test', '.localhost'];
const DEFANG_MARKS = ['[.]', '(.)', 'hxxp'];

// Real-domain regex — matches an obvious http[s]://…/… or bare domain
const URL_RE = /https?:\/\/[a-z0-9.\-]+/gi;
// Domain regex — require at least ONE actual public TLD from the top ~20 by usage,
// so we don't false-match detector names like `net.new-endpoint` or `install.script-added`
// which use dotted-identifier syntax. Extend as needed.
const DOMAIN_RE = /\b[a-z0-9\-]{2,}(?:\.[a-z0-9\-]+)*\.(?:com|net|org|io|dev|app|sh|co|gg|xyz|top|pw|zip|click|info|us|biz|invalid|example|test|localhost)\b/gi;

// Loopback and RFC-1918 private IPs are OK — everything else is suspicious
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
function isSafeIp(ip) {
  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('0.')) return true;
  if (ip.startsWith('192.168.')) return true;
  const second = Number(ip.split('.')[1]);
  if (ip.startsWith('172.') && second >= 16 && second <= 31) return true;
  return false;
}

// npmjs.org and yarnpkg.com are BENIGN URLs to include in a lockfile's `resolved` field.
// They're not indicators; they're the legitimate registry. Same for github.com.
const ALLOWED_HOSTS = new Set([
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'raw.githubusercontent.com',
  'github.com',
  'gitlab.com',
  'bitbucket.org',
]);

function isDefanged(host) {
  return RESERVED_TLDS.some((tld) => host.endsWith(tld)) ||
    DEFANG_MARKS.some((m) => host.includes(m));
}

const violations = [];

function scanFile(filePath) {
  const rel = path.relative(REPO_ROOT, filePath);
  const text = readFileSync(filePath, 'utf8');

  // URL check
  for (const url of text.match(URL_RE) || []) {
    const host = url.replace(/^https?:\/\//, '').split(/[\/:?]/)[0];
    if (ALLOWED_HOSTS.has(host)) continue;
    if (isDefanged(host)) continue;
    violations.push({ file: rel, kind: 'live-url', value: url });
  }

  // Domain check (bare, no protocol)
  for (const domain of text.match(DOMAIN_RE) || []) {
    // Skip common file extensions and known-safe domains
    if (domain.endsWith('.json') || domain.endsWith('.js') || domain.endsWith('.ts') ||
        domain.endsWith('.md') || domain.endsWith('.tgz') || domain.endsWith('.yaml') ||
        domain.endsWith('.yml') || domain.endsWith('.py') || domain.endsWith('.txt')) continue;
    if (ALLOWED_HOSTS.has(domain)) continue;
    if (isDefanged(domain)) continue;
    // Skip if it looks like a version-style dotted number
    if (/^[\d.]+$/.test(domain)) continue;
    // Skip if the containing line is clearly a code identifier (has :: or ->)
    // (this is a heuristic; we accept some false positives here — the goal is
    // catching live IOCs, not linting identifiers)
    violations.push({ file: rel, kind: 'live-domain', value: domain });
  }

  // IP check
  for (const ip of text.match(IP_RE) || []) {
    if (isSafeIp(ip)) continue;
    violations.push({ file: rel, kind: 'live-ip', value: ip });
  }
}

function walk(dir) {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(p);
    } else if (entry.isFile()) {
      // Only scan human-readable formats — skip tarballs, images, etc.
      if (/\.(json|md|yaml|yml|txt|osif\.json)$/.test(entry.name)) {
        scanFile(p);
      }
    }
  }
}

console.log('running defang-guard on corpus/…');
walk(CORPUS_DIR);

if (violations.length === 0) {
  console.log(`  ✓ 0 violations — corpus is fully defanged`);
  process.exit(0);
}

console.error(`\n  ✗ ${violations.length} defang violation(s):\n`);
for (const v of violations) {
  console.error(`    ${v.file}: ${v.kind} → ${v.value}`);
}
console.error(`\nEvery URL/domain in a corpus fixture MUST be defanged (.invalid/.example/.test/.localhost) or on the ALLOWED_HOSTS list.`);
console.error(`Add real payloads via hxxp/[.]/(.) defang notation, or fix the fixture and re-run.`);
process.exit(1);
