// Regression battery for hooks/scope-guard.mjs. Run: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HOOK = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'scope-guard.mjs');
const UA = 'BugBounty-tester';
const BASE = {
  inScope: ['app.example.com', '*.api.example.com'],
  outOfScope: ['admin.example.com'],
  denyUnlisted: ['example.com', '*.example.com'],
  uaTag: UA,
  confirmStateChanging: false,
};

function workspace(scope, { ownHookCopy = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bp-hook-'));
  fs.mkdirSync(path.join(dir, 'notes'));
  fs.writeFileSync(path.join(dir, 'notes', 'scope.json'), JSON.stringify(scope));
  if (ownHookCopy) {
    fs.mkdirSync(path.join(dir, '.claude', 'hooks'), { recursive: true });
    fs.copyFileSync(HOOK, path.join(dir, '.claude', 'hooks', 'scope-guard.mjs'));
  }
  return dir;
}

function decide(input, scope = BASE, opts = {}) {
  const dir = workspace(scope, opts);
  const res = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify(input),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir, BOUNTYPROOF_DRY_RUN: '' },
    encoding: 'utf8',
  });
  assert.equal(res.status, 0, 'the hook must always exit 0 (fail-open)');
  const out = res.stdout.trim() ? JSON.parse(res.stdout).hookSpecificOutput : null;
  return { decision: out ? out.permissionDecision : 'allow', reason: out?.permissionDecisionReason ?? '', dir };
}

const bash = command => ({ tool_name: 'Bash', tool_input: { command } });
const ps = command => ({ tool_name: 'PowerShell', tool_input: { command } });
const nav = url => ({ tool_name: 'mcp__playwright__browser_navigate', tool_input: { url } });
const curl = (url, extra = '') => bash(`curl -A "Mozilla/5.0 ${UA}" ${extra} ${url}`);

function hashOf(s) {
  const canon = a => [...new Set((a || []).map(x => String(x).trim().toLowerCase()).filter(Boolean))].sort().join(',');
  return crypto.createHash('sha256')
    .update(`inScope=${canon(s.inScope)}|outOfScope=${canon(s.outOfScope)}|denyUnlisted=${canon(s.denyUnlisted)}`)
    .digest('hex');
}

test('in-scope GET with the UA tag is allowed', () => {
  assert.equal(decide(curl('https://app.example.com/me')).decision, 'allow');
  assert.equal(decide(curl('https://v1.api.example.com/x')).decision, 'allow');
});

test('out-of-scope host is denied', () => {
  assert.equal(decide(curl('https://admin.example.com/')).decision, 'deny');
});

test('unlisted host under denyUnlisted is denied', () => {
  assert.equal(decide(curl('https://shop.example.com/')).decision, 'deny');
});

test('unknown host is denied, allowHosts and localhost are not', () => {
  assert.equal(decide(curl('https://cdn.vendor.test/lib.js')).decision, 'deny');
  assert.equal(decide(curl('https://cdn.vendor.test/lib.js'), { ...BASE, allowHosts: ['cdn.vendor.test'] }).decision, 'allow');
  assert.equal(decide(bash('curl http://localhost:8080/health')).decision, 'allow');
});

test('missing UA tag or required header is denied', () => {
  assert.equal(decide(bash('curl https://app.example.com/')).decision, 'deny');
  const withHeader = { ...BASE, requiredHeaders: ['X-Bug-Bounty: tester'] };
  assert.equal(decide(curl('https://app.example.com/'), withHeader).decision, 'deny');
  assert.equal(decide(curl('https://app.example.com/', '-H "X-Bug-Bounty: tester"'), withHeader).decision, 'allow');
});

test('Host header pointing at an out-of-scope vhost is denied', () => {
  assert.equal(decide(curl('https://app.example.com/', '-H "Host: admin.example.com"')).decision, 'deny');
});

test('state-changing requests ask only when confirmStateChanging is on', () => {
  const post = curl('https://app.example.com/api/items', '-X POST -d "a=1"');
  assert.equal(decide(post).decision, 'allow');
  assert.equal(decide(post, { ...BASE, confirmStateChanging: true }).decision, 'ask');
});

test('GraphQL queries are reads, mutations ask', () => {
  const on = { ...BASE, confirmStateChanging: true };
  const query = curl('https://app.example.com/graphql', `-d '{"query":"{ me { id } }"}'`);
  const mutation = curl('https://app.example.com/graphql', `-d '{"query":"mutation { delete(id: 1) }"}'`);
  assert.equal(decide(query, on).decision, 'allow');
  assert.equal(decide(mutation, on).decision, 'ask');
});

test('PowerShell Invoke-WebRequest is parsed', () => {
  assert.equal(decide(ps('Invoke-WebRequest -Uri https://admin.example.com/ -UserAgent "x BugBounty-tester"')).decision, 'deny');
  assert.equal(decide(ps('iwr https://app.example.com/ -UserAgent "x BugBounty-tester"')).decision, 'allow');
});

test('Playwright navigation is checked (no UA requirement in the browser)', () => {
  assert.equal(decide(nav('https://admin.example.com/')).decision, 'deny');
  assert.equal(decide(nav('https://app.example.com/')).decision, 'allow');
});

test('requireConfirm blocks until the current scope hash is confirmed', () => {
  const unconfirmed = { ...BASE, requireConfirm: true };
  assert.equal(decide(curl('https://app.example.com/'), unconfirmed).decision, 'deny');
  const confirmed = { ...unconfirmed, confirmedScope: hashOf(unconfirmed) };
  assert.equal(decide(curl('https://app.example.com/'), confirmed).decision, 'allow');
  const widened = { ...confirmed, inScope: [...BASE.inScope, 'new.example.com'] };
  assert.equal(decide(curl('https://app.example.com/'), widened).decision, 'deny');
});

test('the agent cannot confirm the scope itself', () => {
  const scope = { ...BASE, requireConfirm: true };
  assert.equal(decide(bash('bountyproof scope confirm --yes'), scope).decision, 'deny');
  assert.equal(decide(bash('python scripts/bountyproof.py scope   confirm'), scope).decision, 'deny');
  assert.equal(decide(ps('.\\tools\\scripts\\confirm-scope.ps1'), scope).decision, 'deny');
  assert.equal(decide(bash('bash -c "bountyproof scope confirm --yes"'), scope).decision, 'deny');
  assert.equal(decide(ps('& .\\tools\\scripts\\confirm-scope.ps1'), scope).decision, 'deny');
  assert.equal(decide(bash('bountyproof scope check https://app.example.com/'), scope).decision, 'allow');
  // reading or searching for the confirm step is fine
  assert.equal(decide(bash('head -30 tools/scripts/confirm-scope.ps1'), scope).decision, 'allow');
  assert.equal(decide(bash('grep -n "scope confirm" prompts/00-setup-program.md'), scope).decision, 'allow');
  assert.equal(decide(ps('Get-Content tools/scripts/confirm-scope.ps1'), scope).decision, 'allow');
});

test('guard is inactive until inScope is filled', () => {
  assert.equal(decide(curl('https://admin.example.com/'), { ...BASE, inScope: [] }).decision, 'allow');
});

test('non-network commands are ignored', () => {
  assert.equal(decide(bash('ls -la notes/')).decision, 'allow');
});

test('checked requests are logged with secrets redacted', () => {
  const { dir } = decide(curl('https://app.example.com/?token=abc123', '-H "Authorization: Bearer secret"'));
  const log = fs.readFileSync(path.join(dir, 'notes', 'egress-log.jsonl'), 'utf8');
  assert.match(log, /app\.example\.com/);
  assert.doesNotMatch(log, /abc123|Bearer secret/);
});

test('plugin copy steps aside when the workspace has its own hook', () => {
  // HOOK runs from the repo (as the plugin would); the workspace copy is the one that decides.
  assert.equal(decide(curl('https://admin.example.com/'), BASE, { ownHookCopy: true }).decision, 'allow');
});

test('malformed input fails open', () => {
  const dir = workspace(BASE);
  const res = spawnSync(process.execPath, [HOOK], { input: '{not json', env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.equal(res.stdout.trim(), '');
});
