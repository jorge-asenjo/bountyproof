// scope-guard.mjs — PreToolUse hook: deterministic scope enforcement for live engagements.
//
// Reads notes/scope.json (filled in Phase 0) and, for every network command (curl, wget,
// Invoke-WebRequest, scanners, inline python/node) and every Playwright navigation:
//   - DENY  when a destination host is out of scope (OOS wins over in-scope wildcards), or is an
//           unlisted host under a `denyUnlisted` domain ("any *.acme.com not listed is OOS")
//   - DENY  when an in-scope request is missing the program's UA tag / required headers
//   - ASK   when an in-scope request changes state (POST/PUT/PATCH/DELETE, body, GraphQL mutation)
//           — only if notes/scope.json confirmStateChanging is true (template default: false)
//   - DENY  when the host is unknown (not in inScope / outOfScope / allowHosts): the agent resolves it
//           (allowHosts / hunterInfra / inScope) or drops it
// Every checked request is appended (secrets redacted) to notes/egress-log.jsonl.
// The hook's "ask" still prompts in bypassPermissions mode (verified with Claude Code 2.1.299).
//
// Limits: it sees the command text, not what a script does at runtime (a .py file that opens its
// own connections is invisible), and it doesn't see requests made from inside the page via
// browser_evaluate. Fails open (logs the error) so a hook bug can't brick the session.
//
// The same file ships twice: inside the plugin (hooks/hooks.json) and copied into every workspace
// (.claude/hooks/). When a workspace has its own copy, the plugin's copy steps aside so the
// workspace's pinned version is the only one that runs.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const SCOPE_FILE = path.join(projectDir, 'notes', 'scope.json');
const LOG_FILE = path.join(projectDir, 'notes', 'egress-log.jsonl');
const WORKSPACE_COPY = path.join(projectDir, '.claude', 'hooks', 'scope-guard.mjs');

function isWorkspaceCopy() {
  try { return fs.realpathSync(fileURLToPath(import.meta.url)) === fs.realpathSync(WORKSPACE_COPY); } catch { return false; }
}
if (fs.existsSync(WORKSPACE_COPY) && !isWorkspaceCopy()) process.exit(0);

const NET_TOOLS = new Set([
  'curl', 'wget', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'httpx', 'ffuf',
  'nuclei', 'sqlmap', 'nmap', 'gobuster', 'feroxbuster', 'dirsearch', 'katana', 'arjun', 'dalfox',
  'python', 'python3', 'py', 'node', 'openssl', 'ncat', 'nc',
]);
const NET_HINT = /\b(curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm|httpx|ffuf|nuclei|sqlmap|nmap|gobuster|feroxbuster|dirsearch|katana|arjun|dalfox|python3?|py|node|openssl|ncat|nc)\b/i;
// Confirming the scope is the human's step, so the agent can't run it (CLI or PowerShell script).
// Reading or searching for it is fine.
const CONFIRM_RE = /\bscope\s+confirm\b|confirm-scope\.ps1/i;
const READERS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'type', 'get-content', 'gc', 'grep', 'rg', 'findstr', 'select-string',
  'sls', 'sed', 'awk', 'wc', 'ls', 'dir', 'echo', 'printf', 'write-output', 'write-host', 'git', 'diff',
]);
const URL_RE = /\b(?:https?|wss?):\/\/[^\s'"<>`)\]}]+/gi;
const HOST_RE = /(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?![\w-])/gi;
const DEFAULT_ALLOW = [
  'localhost', '127.0.0.1', '::1', 'github.com', '*.github.com', '*.githubusercontent.com',
  'registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org', 'crt.sh', 'web.archive.org',
  '*.yeswehack.com', 'yeswehack.com', '*.intigriti.com', 'intigriti.com', '*.hackerone.com',
  'hackerone.com', '*.anthropic.com', 'claude.ai', '*.claude.ai',
];

// curl options that consume the next token (subset that matters + common ones)
const CURL_SHORT_VAL = new Set('AbcCdDeEFHKmoQrtTuUwxXyYz'.split(''));
const CURL_LONG_VAL = new Set([
  'url', 'user-agent', 'header', 'data', 'data-raw', 'data-binary', 'data-urlencode', 'data-ascii',
  'json', 'form', 'form-string', 'request', 'cookie', 'cookie-jar', 'referer', 'output', 'user',
  'proxy', 'proxy-user', 'resolve', 'connect-to', 'max-time', 'connect-timeout', 'retry',
  'upload-file', 'config', 'write-out', 'dump-header', 'cacert', 'cert', 'key', 'range',
  'limit-rate', 'interface', 'continue-at', 'time-cond', 'variable', 'expand-url', 'expand-header',
]);
const CURL_BODY = new Set(['d', 'F', 'T', 'data', 'data-raw', 'data-binary', 'data-urlencode',
  'data-ascii', 'json', 'form', 'form-string', 'upload-file']);
const PS_VAL = new Set(['uri', 'method', 'body', 'headers', 'useragent', 'outfile', 'contenttype',
  'sessionvariable', 'websession', 'timeoutsec', 'maximumredirection', 'proxy', 'proxycredential',
  'credential', 'infile', 'form', 'certificate', 'certificatethumbprint', 'transferencoding',
  'maximumretrycount', 'retryintervalsec', 'authentication', 'token', 'custommethod', 'httpversion']);
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function log(entry) {
  if (process.env.BOUNTYPROOF_DRY_RUN) return; // `bountyproof scope check` simulates, nothing is sent
  try { fs.appendFileSync(LOG_FILE, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n'); } catch {}
}

function redact(s) {
  return String(s)
    .replace(/((?:authorization|cookie|x-api-key|x-auth-token|proxy-authorization|x-csrf-token)\s*:\s*)[^"'\n]+/gi, '$1[REDACTED]')
    .replace(/(\s(?:-b|--cookie|-u|--user)\s+)("[^"]*"|'[^']*'|\S+)/g, '$1[REDACTED]')
    .replace(/([?&][^=&\s'"]*(?:token|key|secret|pass|code|session|auth|sig)[^=&\s'"]*=)[^&\s'"]+/gi, '$1[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, '[JWT]')
    .slice(0, 600);
}

// Shell-ish tokenizer. Bash escapes with \, PowerShell with ` (backslash is a path separator there).
// Unquoted | ; & ( ) newline split segments; > and < mark the next token as a redirect target.
function segments(cmd, ps) {
  const esc = ps ? '`' : '\\';
  const segs = [[]];
  let cur = '', quote = null, has = false, redirect = false;
  const push = () => {
    if (has) { if (!redirect) segs[segs.length - 1].push(cur); redirect = false; }
    cur = ''; has = false;
  };
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === esc && quote === '"' && i + 1 < cmd.length) cur += cmd[++i];
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; has = true; continue; }
    if (c === esc && i + 1 < cmd.length && cmd[i + 1] !== '\n') { cur += cmd[++i]; has = true; continue; }
    if (/\s/.test(c) && c !== '\n') { push(); continue; }
    if ('|;&()\n'.includes(c)) { push(); segs.push([]); continue; }
    if (c === '>' || c === '<') { push(); redirect = true; while (cmd[i + 1] === '>' || cmd[i + 1] === '&') i++; continue; }
    cur += c; has = true;
  }
  push();
  return segs.filter(s => s.length);
}

function toolName(tok) {
  const base = tok.replace(/^.*[\\/]/, '').toLowerCase();
  return base.endsWith('.exe') ? base.slice(0, -4) : base;
}

function confirmsScope(cmd, ps) {
  if (!CONFIRM_RE.test(cmd)) return false;
  for (const seg of segments(cmd, ps)) {
    let i = 0;
    while (i < seg.length && (seg[i] === '&' || seg[i] === '.' || /^[A-Za-z_]\w*=/.test(seg[i]))) i++;
    if (i >= seg.length || READERS.has(toolName(seg[i]))) continue;
    const words = seg.slice(i).map(t => t.toLowerCase());
    if (words.some(w => w.endsWith('confirm-scope.ps1') || /\bscope\s+confirm\b/.test(w))) return true;
    if (words.some((w, j) => w === 'scope' && words[j + 1] === 'confirm')) return true;
  }
  return false;
}

function hostOf(tok) {
  const t = tok.trim();
  if (/^(?:https?|wss?):\/\//i.test(t)) {
    try { return new URL(t).hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, ''); } catch { return null; }
  }
  const m = /^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(?::\d+)?(?:[/?#].*)?$/i.exec(t);
  if (m && /\.[a-z]{2,}$|^\d+\.\d+\.\d+\.\d+$/i.test(m[1])) return m[1].toLowerCase();
  return null;
}

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  return p.length === 4 && p.every(n => n >= 0 && n <= 255) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : null;
}

function matches(host, pattern) {
  const p = String(pattern).trim().toLowerCase().replace(/^(?:https?:\/\/)/, '').replace(/\/.*$/, '');
  if (!p) return false;
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(String(pattern).trim())) {
    const [net, bits] = String(pattern).split('/');
    const h = ipToInt(host), n = ipToInt(net), b = Number(bits);
    if (h === null || n === null) return false;
    const mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
    return ((h & mask) >>> 0) === ((n & mask) >>> 0);
  }
  if (p.startsWith('*.')) return host.endsWith(p.slice(1)) && host.length > p.length - 1;
  return host === p;
}
const matchAny = (host, list) => (list || []).some(p => matches(host, p));

// ZeroProtocol-style scope confirmation. Canonicalize the confirmed scope sets (lowercased, unique,
// ordinal-sorted) and SHA-256 them. `bountyproof scope confirm` (and tools/scripts/confirm-scope.ps1)
// compute the same hash and write it to scope.confirmedScope. Any edit to inScope/outOfScope/denyUnlisted makes the stored hash stale,
// which — when requireConfirm is true — re-blocks live in-scope testing until a human re-confirms.
function canonList(arr) {
  const set = new Set((arr || []).map(x => String(x).trim().toLowerCase()).filter(Boolean));
  return [...set].sort().join(',');
}
function scopeHash(scope) {
  const s = `inScope=${canonList(scope.inScope)}|outOfScope=${canonList(scope.outOfScope)}|denyUnlisted=${canonList(scope.denyUnlisted)}`;
  return crypto.createHash('sha256').update(s).digest('hex');
}

// Parse one command segment that starts with a network tool. `dests` are explicit destinations
// (an unknown one is DENIED); `mentions` are hostnames merely present in the args (only acted on
// when they match inScope/outOfScope, so file names and payload strings don't cause prompts).
function parseSegment(tool, args) {
  const r = { tool, dests: [], mentions: [], ua: '', headers: [], method: '', body: '', hasBody: false, getFlag: false };
  if (tool === 'curl') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a.startsWith('--')) {
        let [name, val] = a.slice(2).split(/=(.*)/s);
        if (CURL_LONG_VAL.has(name)) { if (val === undefined) val = args[++i] ?? ''; } else val = undefined;
        if (name === 'get') r.getFlag = true;
        if (val === undefined) continue;
        if (name === 'url') r.dests.push(val);
        else if (name === 'user-agent') r.ua = val;
        else if (name === 'header') r.headers.push(val);
        else if (name === 'request') r.method = val.toUpperCase();
        if (CURL_BODY.has(name)) { r.hasBody = true; r.body += ' ' + val; }
      } else if (a.startsWith('-') && a.length > 1) {
        const chars = a.slice(1);
        for (let j = 0; j < chars.length; j++) {
          const ch = chars[j];
          if (ch === 'G') r.getFlag = true;
          if (!CURL_SHORT_VAL.has(ch)) continue;
          const val = j + 1 < chars.length ? chars.slice(j + 1) : (args[++i] ?? '');
          if (ch === 'A') r.ua = val;
          else if (ch === 'H') r.headers.push(val);
          else if (ch === 'X') r.method = val.toUpperCase();
          if (CURL_BODY.has(ch)) { r.hasBody = true; r.body += ' ' + val; }
          break;
        }
      } else r.dests.push(a);
    }
    if (!r.method) r.method = r.hasBody && !r.getFlag ? 'POST' : 'GET';
  } else if (['invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm'].includes(tool)) {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (/^-[a-z]/i.test(a)) {
        const name = a.slice(1).replace(/:$/, '').toLowerCase();
        if (!PS_VAL.has(name)) continue;
        const val = args[++i] ?? '';
        if (name === 'uri') r.dests.push(val);
        else if (name === 'method' || name === 'custommethod') r.method = val.toUpperCase();
        else if (name === 'useragent') r.ua = val;
        else if (name === 'headers') r.headers.push(val);
        else if (['body', 'infile', 'form'].includes(name)) { r.hasBody = true; r.body += ' ' + val; }
      } else r.dests.push(a);
    }
    if (!r.method) r.method = 'GET';
  } else {
    // Generic tools (wget, scanners, inline python/node): wget URLs are explicit destinations;
    // for the rest every URL/hostname is only a mention.
    const text = args.join(' ');
    const urls = text.match(URL_RE) || [];
    (tool === 'wget' ? r.dests : r.mentions).push(...urls);
    for (const m of text.matchAll(HOST_RE)) r.mentions.push(m[1]);
    const ua = /(?:--user-agent|-U|-A|User-Agent:)\s*=?\s*("[^"]*"|'[^']*'|[^\s]+)/i.exec(text);
    if (ua) r.ua = ua[1];
    r.headers.push(text);
    const mm = /(?:-X\s*|--request\s+|-Method\s+|method\s*[:=]\s*['"]?|\.)(post|put|patch|delete)\b/i.exec(text);
    r.method = mm ? mm[1].toUpperCase() : 'GET';
    r.body = text;
  }
  return r;
}

function decide(input, scope) {
  const tname = input.tool_name || '';
  const ti = input.tool_input || {};
  const reqs = [];
  let raw = '';

  if (tname.startsWith('mcp__playwright__')) {
    if (!ti.url) return null;
    raw = `${tname} ${ti.url}`;
    reqs.push({ tool: 'browser', dests: [ti.url], mentions: [], ua: '(browser)', headers: [], method: 'GET', body: '', hasBody: false });
  } else {
    raw = String(ti.command || '');
    if (confirmsScope(raw, tname === 'PowerShell')) {
      log({ tool: tname, decision: 'deny', reasons: ['scope confirmation attempted by the agent'], cmd: redact(raw) });
      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: "[scope-guard] Confirming the scope is the human's step. Ask them to review notes/scope.json against the program page and run `bountyproof scope confirm` in their own terminal.",
        },
      };
    }
    if (!NET_HINT.test(raw)) return null;
    for (const seg of segments(raw, tname === 'PowerShell')) {
      const idx = seg.findIndex(t => NET_TOOLS.has(toolName(t)));
      if (idx === -1) continue;
      reqs.push(parseSegment(toolName(seg[idx]), seg.slice(idx + 1)));
    }
    if (!reqs.length) return null;
  }

  const inScope = scope.inScope || [], oos = scope.outOfScope || [];
  const allow = [...DEFAULT_ALLOW, ...(scope.allowHosts || []), ...(scope.hunterInfra || [])];
  const deny = [], ask = [], hosts = [];
  // Scope confirmation stale? (only when the program opts in via requireConfirm)
  const expectedHash = scope.requireConfirm === true ? scopeHash(scope) : '';
  const staleConfirm = expectedHash && expectedHash !== (scope.confirmedScope || '');

  for (const r of reqs) {
    const explicit = new Set(r.dests.map(hostOf).filter(Boolean));
    // A Host: header override points the request at another vhost
    for (const h of r.headers) {
      const m = /^\s*host\s*:\s*([^\s"']+)/im.exec(h);
      if (m) explicit.add(m[1].toLowerCase().replace(/:\d+$/, ''));
    }
    const mentioned = new Set(r.mentions.map(hostOf).filter(h => h && !explicit.has(h)));
    const stateChanging = !READ_METHODS.has(r.method);
    for (const host of [...explicit, ...mentioned]) {
      let cls;
      if (matchAny(host, oos)) cls = 'OOS';
      else if (matchAny(host, inScope)) cls = 'IN_SCOPE';
      else if (matchAny(host, scope.denyUnlisted)) cls = 'OOS_UNLISTED';
      else if (!explicit.has(host)) continue; // unmatched mention: file name, payload string, etc.
      else if (matchAny(host, allow) || /^(10|127)\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(host)) cls = 'ALLOWED';
      else cls = 'UNKNOWN';
      hosts.push({ host, cls, method: r.method });

      if (cls === 'OOS') { deny.push(`${host} is OUT OF SCOPE (notes/scope.json outOfScope). Do not send requests there.`); continue; }
      if (cls === 'OOS_UNLISTED') { deny.push(`${host} is not listed in inScope and its domain is under denyUnlisted (unlisted hosts = out of scope). Do not send requests there.`); continue; }
      if (cls === 'UNKNOWN') { deny.push(`${host} is not in notes/scope.json. Non-target helper (docs/CDN) → add to allowHosts; your OOB → hunterInfra; listed by the program → inScope; otherwise drop it.`); continue; }
      if (cls === 'IN_SCOPE' && staleConfirm) {
        deny.push(`Scope not confirmed for the current notes/scope.json (it changed, or was never confirmed). Review inScope/outOfScope, then run \`bountyproof scope confirm\` (or tools/scripts/confirm-scope.ps1) before testing ${host}. requireConfirm=true blocks live in-scope testing until confirmed.`);
        continue;
      }
      if (cls !== 'IN_SCOPE' || r.tool === 'browser') continue;

      const reqText = [r.ua, ...r.headers].join('\n').toLowerCase();
      if (scope.uaTag && !reqText.includes(String(scope.uaTag).toLowerCase()))
        deny.push(`Request to in-scope ${host} is missing the program UA tag. Add: -A "<browser UA> ${scope.uaTag}" (or -UserAgent in PowerShell).`);
      for (const h of scope.requiredHeaders || [])
        if (!reqText.includes(String(h).toLowerCase())) deny.push(`Request to in-scope ${host} is missing required header: ${h}`);

      const isGraphqlRead = /graphql/i.test(r.dests.join(' ')) && !/\bmutation\b/i.test(r.body);
      if (scope.confirmStateChanging !== false && stateChanging && !isGraphqlRead)
        ask.push(`State-changing ${r.method} to LIVE in-scope host ${host}. Confirm this is your own test account/object and the action is non-destructive.`);
    }
  }

  const decision = deny.length ? 'deny' : ask.length ? 'ask' : null;
  if (hosts.length) log({ tool: tname, decision: decision || 'allow', hosts, reasons: [...deny, ...ask], cmd: redact(raw) });
  if (!decision) return null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: `[scope-guard] ${(decision === 'deny' ? deny : ask).join(' | ')}`,
    },
  };
}

let buf = '';
process.stdin.on('data', c => (buf += c)).on('end', () => {
  try {
    const input = JSON.parse(buf);
    const scope = readJson(SCOPE_FILE);
    if (!scope || scope.enforce === false || !(scope.inScope || []).length) process.exit(0);
    const out = decide(input, scope);
    if (out) process.stdout.write(JSON.stringify(out));
    process.exit(0);
  } catch (e) {
    log({ error: String(e && e.stack || e) });
    process.exit(0);
  }
});
