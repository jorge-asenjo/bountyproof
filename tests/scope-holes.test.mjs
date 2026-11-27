// Scope holes, one test per kind: how a host is written, how rules are written, and what comes from
// outside (redirects, recon lists, a broken scope.json). Each case is a way a request could reach a
// host the program didn't authorize while the guard looked elsewhere. Run: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HOOK = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'scope-guard.mjs');
const UA = 'BugBounty-tester';
const BASE = {
  inScope: ['app.example.com', '*.api.example.com', '203.0.113.0/28', '2001:db8:1::/48'],
  outOfScope: ['admin.example.com', 'legacy.api.example.com', '203.0.113.9', '2001:db8:1::bad'],
  denyUnlisted: ['example.com', '*.example.com'],
  uaTag: UA,
};

function workspace(scope, files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bp-holes-'));
  fs.mkdirSync(path.join(dir, 'notes'));
  if (scope !== null) {
    fs.writeFileSync(path.join(dir, 'notes', 'scope.json'), typeof scope === 'string' ? scope : JSON.stringify(scope));
  }
  for (const [rel, text] of Object.entries(files)) fs.writeFileSync(path.join(dir, rel), text);
  return dir;
}

function run(input, scope = BASE, files = {}, dir = workspace(scope, files)) {
  const res = spawnSync(process.execPath, [HOOK], {
    input: typeof input === 'string' ? input : JSON.stringify(input),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir, BOUNTYPROOF_DRY_RUN: '1' },
    encoding: 'utf8',
  });
  assert.equal(res.status, 0, `the hook must exit 0 (stderr: ${res.stderr})`);
  const out = res.stdout.trim() ? JSON.parse(res.stdout) : {};
  const hso = out.hookSpecificOutput || {};
  return { decision: hso.permissionDecision || 'allow', reason: hso.permissionDecisionReason || '', out, dir };
}

const bash = command => ({ tool_name: 'Bash', tool_input: { command } });
const ps = command => ({ tool_name: 'PowerShell', tool_input: { command } });
const nav = url => ({ tool_name: 'mcp__playwright__browser_navigate', tool_input: { url } });
const curl = rest => bash(`curl -A "Mozilla/5.0 ${UA}" ${rest}`);
const decision = (input, scope, files) => run(input, scope, files).decision;

// ---------------------------------------------------------------- the host

test('host: case, trailing dot and port name the same host', () => {
  assert.equal(decision(curl('https://ADMIN.Example.COM/')), 'deny');
  assert.equal(decision(curl('https://admin.example.com./')), 'deny');
  assert.equal(decision(curl('https://admin.example.com:8443/')), 'deny');
  assert.equal(decision(curl('admin.example.com:8443/x')), 'deny');
  assert.equal(decision(curl('https://App.Example.com./me')), 'allow');
});

test('host: userinfo before @ is not the host, with or without a scheme', () => {
  assert.equal(decision(curl('http://app.example.com@evil.test/')), 'deny');
  assert.equal(decision(curl('app.example.com@evil.test/x')), 'deny'); // curl adds http:// and goes to evil.test
  assert.equal(decision(curl('http://app.example.com@admin.example.com/')), 'deny');
  assert.equal(decision(curl('"http://a.example.com@b.example.com@app.example.com/"')), 'deny'); // several @
});

test('host: a backslash, space or control character in the authority is ambiguous', () => {
  // urlparse-style parsers and HTTP clients disagree on where the host ends (their #247)
  assert.equal(decision(curl(String.raw`'http://app.example.com\@admin.example.com/'`)), 'deny');
  assert.equal(decision(curl(String.raw`'http://admin.example.com\@app.example.com/'`)), 'deny');
  // a backslash in the path or query is fine (Windows LFI payloads)
  assert.equal(decision(curl(String.raw`'https://app.example.com/dl?file=..\..\win.ini'`)), 'allow');
});

test('host: IPv4 written in decimal, hex or octal is the address the client connects to', () => {
  assert.equal(decision(curl('3405803785')), 'deny'); // 203.0.113.9 (out of scope) in decimal, no scheme
  assert.equal(decision(curl('http://3405803785/')), 'deny');
  assert.equal(decision(curl('http://0xcb.0.0x71.9/')), 'deny');
  // octal: 011 is 9, so curl goes to 203.0.113.9 (out of scope), not .11 (in scope)
  assert.equal(decision(curl('203.0.113.011')), 'deny');
  assert.equal(decision(curl('http://203.0.113.5/')), 'allow');
});

test('host: IPv6 literals, CIDRs and IPv4-mapped addresses', () => {
  assert.equal(decision(curl("'http://[2001:db8:1::5]/'")), 'allow'); // in-scope IPv6 CIDR
  assert.equal(decision(curl("'http://[2001:0db8:0001:0000:0000:0000:0000:0bad]/'")), 'deny'); // non-canonical OOS
  assert.equal(decision(curl("'http://[2001:db8:2::1]/'")), 'deny'); // outside the CIDR
  assert.equal(decision(curl("'http://[::ffff:203.0.113.9]/'")), 'deny'); // IPv4-mapped OOS address
  const oosV6 = { ...BASE, outOfScope: [...BASE.outOfScope, '2001:0DB8:1::0BAD:1'] }; // rule written long-hand
  assert.equal(decision(curl("'http://[2001:db8:1::bad:1]/'"), oosV6), 'deny');
});

test('host: Unicode, fullwidth and percent-encoded hosts never pass as something else', () => {
  // fullwidth "admin": curl (libidn2) and browsers map it to admin.example.com
  assert.equal(decision(curl('ａｄｍｉｎ.example.com')), 'deny');
  assert.equal(decision(curl('https://ａｄｍｉｎ.example.com/')), 'deny');
  assert.equal(decision(curl('admin%2eexample.com')), 'deny'); // curl decodes %2e in the host
  // a look-alike host under an in-scope wildcard: write it in punycode or don't send it
  assert.equal(decision(curl('https://аpp.api.example.com/')), 'deny'); // Cyrillic а
  assert.equal(decision(nav('https://аpp.api.example.com/')), 'deny');
  // the punycode spelling is checked like any other host
  assert.equal(decision(curl('https://xn--pp-6kc.api.example.com/')), 'allow');
});

test('host: an out-of-scope IDN written in Unicode in scope.json is not silently ignored', () => {
  // CWE-176: the rule and the host are two encodings of one name. A rule the guard can't match
  // exactly makes the scope invalid, so nothing goes out until it's written in punycode.
  const scope = { ...BASE, outOfScope: [...BASE.outOfScope, 'тест.api.example.com'] };
  const r = run(curl('https://xn--e1aybc.api.example.com/'), scope);
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, /xn--e1aybc\.api\.example\.com/); // tells you the punycode to write
});

test('host: curl globs in the host expand to hosts the guard never sees', () => {
  assert.equal(decision(curl('"https://{v1,legacy}.api.example.com/"')), 'deny');
  assert.equal(decision(curl('"https://legac[x-y].api.example.com/"')), 'deny');
  assert.equal(decision(curl('"https://app.example.com/items/[1-20]"')), 'allow'); // a glob in the path is fine
});

test('host: a private-IP prefix on a hostname is not a private IP', () => {
  assert.equal(decision(bash('curl https://10.evil.test/')), 'deny');
  assert.equal(decision(bash('curl http://127.0.0.1.nip.test/')), 'deny');
  assert.equal(decision(bash('curl http://10.1.2.3:8080/')), 'allow');
});

test('host: a URL the guard cannot read is not a URL it can ignore', () => {
  assert.equal(decision(curl('$TARGET')), 'deny');
  assert.equal(decision(curl('"https://$HOST/api"')), 'deny');
  assert.equal(decision(ps(`curl.exe -A "x ${UA}" $u`)), 'deny');
  assert.equal(decision(curl('-K urls.txt')), 'deny'); // URLs in a config file
  assert.equal(decision(bash('cat urls.txt | xargs curl -s')), 'deny');
  assert.equal(decision(bash('curl --version')), 'allow');
  assert.equal(decision(curl('https://app.example.com/ 2>/dev/null')), 'allow'); // fd redirect, not a URL
  assert.equal(decision(curl('https://app.example.com/ -o out.json --keepalive-time 60')), 'allow');
});

test('host: a variable assigned in the same command is checked as the URL it holds', () => {
  // how agents really write it: the base URL in a variable, then many requests
  assert.equal(decision(bash(`U="x ${UA}"; B=https://app.example.com
curl -A "$U" $B/api/me; curl -A "$U" "\${B}/api/orders"`)), 'allow');
  assert.equal(decision(bash(`B=https://admin.example.com && curl -A "x ${UA}" $B/`)), 'deny');
  assert.equal(decision(bash(`U="-A x-${UA}"; B=http://203.0.113.5; for p in a b; do curl -s $U $B/api/$p; done`)), 'allow');
  assert.equal(decision(ps(`$B = "https://app.example.com"; curl.exe -A "x ${UA}" "$B/api/me"`)), 'allow');
  assert.equal(decision(ps(`$b='https://admin.example.com'; curl.exe -A "x ${UA}" "$B/x"`)), 'deny');
  // what the guard can't see stays denied: command output, a variable used before it is set, the environment
  assert.equal(decision(bash(`B=$(cat base.txt); curl -A "x ${UA}" $B/api`)), 'deny');
  assert.equal(decision(bash(`curl -A "x ${UA}" $B/api; B=https://app.example.com`)), 'deny');
  assert.equal(decision(bash(`B=https://app.example.com curl -A "x ${UA}" $B/api`)), 'deny'); // a prefix assignment isn't seen by $B
  assert.equal(decision(bash(`run(){ curl -A "x ${UA}" "$@"; }; run https://app.example.com/`)), 'deny');
});

test('host: --connect-to and --resolve send the connection somewhere else', () => {
  assert.equal(decision(curl('--connect-to app.example.com:443:admin.example.com:443 https://app.example.com/')), 'deny');
  assert.equal(decision(curl('--resolve app.example.com:443:203.0.113.9 https://app.example.com/')), 'deny');
  assert.equal(decision(curl('--resolve app.example.com:443:203.0.113.5 https://app.example.com/')), 'allow');
});

// ---------------------------------------------------------------- the rules

test('rules: an out-of-scope rule written like the program page still denies', () => {
  // their #182: a port, a trailing dot, backticks or a trailing comma made the deny rule match nothing,
  // and the in-scope wildcard let the host through
  for (const rule of ['legacy.api.example.com:8443', 'legacy.api.example.com.', '`legacy.api.example.com`',
    'legacy.api.example.com,', 'https://legacy.api.example.com/admin', 'LEGACY.API.EXAMPLE.COM']) {
    const scope = { ...BASE, outOfScope: ['admin.example.com', rule] };
    assert.equal(decision(curl('https://legacy.api.example.com/'), scope), 'deny', rule);
  }
});

test('rules: wildcard depth', () => {
  assert.equal(decision(curl('https://a.b.api.example.com/')), 'allow'); // any depth below
  assert.equal(decision(curl('https://api.example.com/')), 'deny'); // the apex isn't included
  assert.equal(decision(curl('https://evilapi.example.com/')), 'deny'); // suffix confusion
  assert.equal(decision(curl('https://x.app.example.com/')), 'deny'); // an exact host has no subdomains
  const noFence = { ...BASE, denyUnlisted: [] };
  assert.equal(decision(curl('https://x.app.example.com/'), noFence), 'deny');
  assert.equal(decision(curl('https://api.example.com.evil.test/'), noFence), 'deny');
});

test('rules: out of scope wins over an in-scope wildcard, at any depth', () => {
  assert.equal(decision(curl('https://legacy.api.example.com/')), 'deny');
  const deep = { ...BASE, outOfScope: ['*.internal.api.example.com'] };
  assert.equal(decision(curl('https://x.internal.api.example.com/'), deep), 'deny');
  assert.equal(decision(curl('https://internal.api.example.com/'), deep), 'allow');
  const mid = { ...BASE, outOfScope: ['legacy-*.api.example.com'] }; // a mid-label wildcard on the deny side
  assert.equal(decision(curl('https://legacy-v2.api.example.com/'), mid), 'deny');
  assert.equal(decision(curl('https://v2.api.example.com/'), mid), 'allow');
});

test('rules: an in-scope wildcard over a whole TLD or public suffix is refused', () => {
  for (const rule of ['*.com', '*.co.uk', '*', 'api-*.example.com']) {
    const scope = { ...BASE, inScope: [...BASE.inScope, rule] };
    assert.equal(decision(curl('https://app.example.com/'), scope), 'deny', rule);
  }
});

// ---------------------------------------------------------------- what comes from outside

test('outside: following redirects from an in-scope host is denied', () => {
  for (const cmd of ['-L https://app.example.com/', '-sSL https://app.example.com/', '--location https://app.example.com/']) {
    const r = run(curl(cmd));
    assert.equal(r.decision, 'deny', cmd);
    assert.match(r.reason, /redirect/i);
  }
  assert.equal(decision(curl('-L --max-redirs 0 https://app.example.com/')), 'allow');
  assert.equal(decision(bash('curl -sL -o tool.zip https://github.com/org/tool/releases/download/v1/tool.zip')), 'allow');
  assert.equal(decision(bash(`wget -U "x ${UA}" https://app.example.com/`)), 'deny'); // wget follows by default
  assert.equal(decision(bash(`wget --max-redirect=0 -U "x ${UA}" https://app.example.com/`)), 'allow');
  assert.equal(decision(ps(`iwr https://app.example.com/ -UserAgent "x ${UA}"`)), 'deny'); // so does iwr
  assert.equal(decision(ps(`iwr https://app.example.com/ -UserAgent "x ${UA}" -MaximumRedirection 0`)), 'allow');
});

test('outside: hosts from recon reach a prober only through a list the guard can read', () => {
  const subs = { 'subs.txt': 'app.example.com\nv1.api.example.com\nadmin.example.com\n' };
  const clean = { 'subs.txt': 'https://app.example.com\nv1.api.example.com\n' };
  const h = `-H "User-Agent: x ${UA}"`;
  assert.equal(decision(bash(`cat subs.txt | httpx -silent ${h}`), BASE, subs), 'deny'); // stdin: invisible
  assert.equal(decision(bash(`subfinder -d example.com -silent | httpx ${h}`)), 'deny');
  const listed = run(bash(`httpx -l subs.txt ${h}`), BASE, subs);
  assert.equal(listed.decision, 'deny');
  assert.match(listed.reason, /admin\.example\.com/);
  assert.equal(decision(bash(`httpx -l subs.txt ${h}`), BASE, clean), 'allow');
  assert.equal(decision(bash(`httpx -l missing.txt ${h}`)), 'deny');
  assert.equal(decision(bash(`nuclei -u https://unknown.vendor.test ${h}`)), 'deny');
  assert.equal(decision(bash(`ffuf -u https://admin.example.com/FUZZ -w words.txt ${h}`)), 'deny');
  assert.equal(decision(bash(`ffuf -u https://app.example.com/FUZZ -w words.txt ${h}`)), 'allow');
});

test('outside: a broken scope.json blocks network commands instead of switching the guard off', () => {
  for (const broken of ['{"inScope": ["app.example.com"],}', '{"inScope": ']) {
    assert.equal(decision(bash('curl https://github.com/'), broken), 'deny', broken);
    assert.equal(decision(nav('https://app.example.com/'), broken), 'deny', broken);
    assert.equal(decision(bash('ls notes'), broken), 'allow'); // nothing to check without a network tool
  }
  const typed = [
    { ...BASE, outOfScope: 'admin.example.com' }, // a string, not a list
    { ...BASE, inScope: 'app.example.com' },
    { ...BASE, requireConfirm: 'true' },
    { ...BASE, inScope: [...BASE.inScope, 'All assets of Example Corp'] },
    { ...BASE, outOfScope: [...BASE.outOfScope, { host: 'x.example.com' }] },
    ['app.example.com'],
  ];
  for (const scope of typed) {
    const r = run(curl('https://app.example.com/'), scope);
    assert.equal(r.decision, 'deny', JSON.stringify(scope));
    assert.match(r.reason, /scope\.json/);
  }
});

test('outside: scope.json saved with a BOM (Windows PowerShell 5.1) is still enforced', () => {
  const withBom = '﻿' + JSON.stringify(BASE);
  assert.equal(decision(curl('https://admin.example.com/'), withBom), 'deny');
  assert.equal(decision(curl('https://app.example.com/'), withBom), 'allow');
});

test('outside: no scope.json means this is not an engagement workspace', () => {
  assert.equal(decision(bash('curl https://anything.test/'), null), 'allow');
});

test('an internal error lets the command through but warns the human loudly', () => {
  const r = run('{not json');
  assert.equal(r.decision, 'allow');
  assert.match(r.out.systemMessage || '', /scope-guard/i);
  assert.match(r.out.systemMessage || '', /NOT checked/);
});

// ---------------------------------------------------------------- scope.json belongs to the human

test('the agent changing scope.json or the guard asks the human once the scope is live', () => {
  const edit = (file_path, tool_name = 'Edit') => ({ tool_name, tool_input: { file_path, old_string: 'a', new_string: 'b' } });
  assert.equal(decision(edit('notes/scope.json')), 'ask');
  const dir = workspace(BASE);
  const write = { tool_name: 'Write', tool_input: { file_path: path.join(dir, 'notes', 'scope.json'), content: '{}' } };
  assert.equal(run(write, BASE, {}, dir).decision, 'ask');
  assert.equal(decision(edit('.claude/hooks/scope-guard.mjs')), 'ask');
  assert.equal(decision(edit('.claude/settings.local.json')), 'ask');
  assert.equal(decision(edit('notes/case-file.md')), 'allow');
  assert.equal(decision(bash(`sed -i 's/"enforce": true/"enforce": false/' notes/scope.json`)), 'ask');
  assert.equal(decision(ps(`(Get-Content notes/scope.json) -replace 'true','false' | Set-Content notes/scope.json`)), 'ask');
  assert.equal(decision(bash('cat notes/scope.json')), 'allow');
  assert.equal(decision(bash('git commit -qm "Update notes/scope.json after the import"')), 'allow');
  assert.equal(decision(bash('cp /tmp/wider.json notes/scope.json')), 'ask');
  // Phase 0 fills it before the guard is live
  assert.equal(decision(edit('notes/scope.json'), { ...BASE, inScope: [] }), 'allow');
});

// ---------------------------------------------------------------- the agents know the scope

test('every session and subagent starts with the scope, out-of-scope list first', () => {
  for (const input of [{ hook_event_name: 'SessionStart', source: 'startup' },
    { hook_event_name: 'SubagentStart', agent_type: 'bountyproof:validator', agent_id: 'a1' }]) {
    const { out } = run(input);
    const ctx = out.hookSpecificOutput?.additionalContext || '';
    assert.equal(out.hookSpecificOutput?.hookEventName, input.hook_event_name);
    assert.match(ctx, /OUT OF SCOPE[^\n]*admin\.example\.com/);
    assert.match(ctx, /legacy\.api\.example\.com/);
    assert.match(ctx, /app\.example\.com/);
    assert.match(ctx, new RegExp(UA));
    assert.ok(ctx.indexOf('OUT OF SCOPE') < ctx.indexOf('IN SCOPE'), 'exclusions come first');
  }
  // nothing to say before Phase 0, or outside a workspace
  assert.equal(run({ hook_event_name: 'SessionStart', source: 'startup' }, { ...BASE, inScope: [] }).out.hookSpecificOutput, undefined);
  assert.equal(run({ hook_event_name: 'SessionStart', source: 'startup' }, null).out.hookSpecificOutput, undefined);
});

test('commands inside commands: heredocs, $(...) and bash -c', () => {
  // text written to a file is not a command, even with curl examples in it
  const report = "cat > reports/H-001.md <<'EOF'\n# H-001\ncurl -s https://admin.example.com/ # the excluded host, as text\ncurl\nEOF\necho done";
  assert.equal(decision(bash(report)), 'allow');
  // a shell or an interpreter reading a heredoc runs it
  assert.equal(decision(bash("bash <<'EOF'\ncurl -A x https://admin.example.com/\nEOF")), 'deny');
  assert.equal(decision(bash("python - <<'EOF'\nimport requests; requests.get('https://admin.example.com/')\nEOF")), 'deny');
  assert.equal(decision(bash(`bash -c "curl -A 'x ${UA}' https://admin.example.com/"`)), 'deny');
  assert.equal(decision(ps(`pwsh -c "curl.exe -A 'x ${UA}' https://admin.example.com/"`)), 'deny');
  // a command substitution is a command, and its output is not a host the guard can read
  assert.equal(decision(bash('echo $(curl -s https://admin.example.com/)')), 'deny');
  const token = `TA=$(python -c "import json;print(json.load(open('a.json'))['token'])")`;
  assert.equal(decision(bash(`${token}; curl -A "x ${UA}" -H "Authorization: Bearer $TA" https://app.example.com/api`)), 'allow');
  assert.equal(decision(bash(`curl -A "x ${UA}" "https://$(cat host.txt)/api"`)), 'deny');
  // a PowerShell here-string is one argument
  const noAsk = { ...BASE, confirmStateChanging: false };
  assert.equal(decision(ps(`$body = @'\n{"url": "https://admin.example.com/"}\n'@\ncurl.exe -A "x ${UA}" -d $body https://app.example.com/api`), noAsk), 'allow');
  // code that only edits notes names hosts as text; code that can send is checked
  assert.equal(decision(bash("python - <<'EOF'\nopen('notes/case-file.md','a').write('admin.example.com is out, app.example.com done')\nEOF")), 'allow');
  assert.equal(decision(bash(`python -c "import urllib.request as u; u.urlopen('https://admin.example.com/')"`)), 'deny');
});
