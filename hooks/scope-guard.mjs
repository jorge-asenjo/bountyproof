// scope-guard.mjs — deterministic scope enforcement for live engagements (Claude Code hook).
//
// PreToolUse: reads notes/scope.json (filled in Phase 0) and, for every network command (curl, wget,
// Invoke-WebRequest, probers and scanners, inline python/node) and every Playwright or Claude in
// Chrome navigation:
//   - DENY  a destination host that is out of scope (outOfScope wins over in-scope wildcards), that is
//           unlisted under a `denyUnlisted` domain, or that isn't in scope.json at all (UNKNOWN)
//   - DENY  a destination the guard can't read for sure: a shell variable, a curl glob, userinfo
//           tricks, a backslash or a non-ASCII character in the host, a target list in a pipe
//   - DENY  following redirects from an in-scope host (curl -L, wget and iwr by default): the next
//           hop is a host the guard never sees, so the agent requests it explicitly
//   - DENY  an in-scope request without the program's UA tag / required headers
//   - ASK   a state-changing in-scope request, only if confirmStateChanging is true (default: false)
//   - DENY  Claude in Chrome on an in-scope host: it drives the human's own Chrome (their sessions,
//           no UA tag) and is only for the platform's report form; the target is tested in Playwright
//   - ASK   a Claude in Chrome click or key press that its action_summary calls a submit/send/publish
//   - ASK   the agent changing notes/scope.json, this hook or the workspace settings once the scope is
//           live: the scope is the human's, and confirming it is the human's step
//   - DENY  the agent running `bountyproof scope confirm` (or confirm-scope.ps1)
// A scope.json that doesn't parse, or has an entry the guard can't enforce exactly, blocks every
// network command until it's fixed. An internal error lets the call through (a guard bug must not
// brick the session) but tells the human, loudly, that the call was not checked.
// SessionStart / SubagentStart: puts the scope in the agent's context, out-of-scope list first, so
// the agents know the exclusions before the hook has to stop them.
// Every checked request is appended (secrets redacted) to notes/egress-log.jsonl.
// The hook's "ask" still prompts in bypassPermissions mode (verified with Claude Code 2.1.299).
//
// Limits: it sees the command text, not what a script does at runtime (a .py file that opens its own
// connections is invisible), and it doesn't see requests made from inside the page (browser_evaluate,
// javascript_tool), where a clicked link leads, or where a browser redirect lands. It doesn't resolve
// DNS, so an in-scope name that points into an excluded network isn't caught.
//
// The same file ships twice: inside the plugin (hooks/hooks.json) and copied into every workspace
// (.claude/hooks/). When a workspace has its own copy, the plugin's copy steps aside so the
// workspace's pinned version is the only one that runs. src/bountyproof/scope.py mirrors the host and
// rule functions below; tests/scope-cases.json holds the cases both must agree on.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { domainToASCII, fileURLToPath } from 'node:url';

const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const SCOPE_FILE = path.join(projectDir, 'notes', 'scope.json');
const LOG_FILE = path.join(projectDir, 'notes', 'egress-log.jsonl');
const WORKSPACE_COPY = path.join(projectDir, '.claude', 'hooks', 'scope-guard.mjs');
const SELF = fileURLToPath(import.meta.url);

// ------------------------------------------------------------------------------------------------
// Hosts and rules (mirrored in src/bountyproof/scope.py)
// ------------------------------------------------------------------------------------------------

const ASCII_WS = /^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g;
const SCHEME = /^([a-z][a-z0-9+.-]*):\/\//i;
const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
const DOTTED_QUAD = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
// Second-level labels that form a public suffix under a two-letter country code (co.uk, com.au...).
const SLD = new Set(['ac', 'co', 'com', 'edu', 'gov', 'gob', 'go', 'ltd', 'mil', 'ne', 'net', 'nic', 'or', 'org', 'plc', 'sch']);
const RULE_LISTS = { inScope: 'in', outOfScope: 'out', denyUnlisted: 'out', allowHosts: 'allow', hunterInfra: 'allow' };
const BOOL_FIELDS = ['enforce', 'requireConfirm', 'confirmStateChanging'];
const STRING_FIELDS = ['uaTag', 'confirmedScope'];
const DEFAULT_ALLOW = [
  'localhost', '127.0.0.1', '::1', 'github.com', '*.github.com', '*.githubusercontent.com',
  'registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org', 'crt.sh', 'web.archive.org',
  '*.yeswehack.com', 'yeswehack.com', '*.intigriti.com', 'intigriti.com', '*.hackerone.com',
  'hackerone.com', '*.bugcrowd.com', 'bugcrowd.com', '*.anthropic.com', 'claude.ai', '*.claude.ai',
];

const stripWs = s => String(s).replace(ASCII_WS, '');
const isIPv4 = h => DOTTED_QUAD.test(h);
const isIP = h => isIPv4(h) || h.includes(':');

/** The host a client connects to for `token` (a URL, or a bare host as curl reads it), or why it can't be told. */
export function canonHost(token) {
  const t = stripWs(token);
  const m = SCHEME.exec(t);
  if (m && m[1].toLowerCase() === 'file') return { local: true };
  const rest = m ? t.slice(m[0].length) : t;
  const end = rest.search(/[/?#]/);
  return fromAuthority(end < 0 ? rest : rest.slice(0, end));
}

function fromAuthority(auth) {
  if (!auth) return { problem: 'there is no host' };
  if (/[^\x21-\x7e]/.test(auth)) {
    return { problem: 'the host has a non-ASCII, space or control character (write an IDN host in punycode, xn--...)' };
  }
  if (auth.includes('$')) return { problem: 'the host is a shell variable or a placeholder: write it literally so the guard can check it' };
  if (/[{}]/.test(auth)) return { problem: 'a curl glob in the host expands to hosts the guard never sees' };
  if (/[\\%|^`<>"']/.test(auth)) return { problem: 'the host has a character that HTTP clients read differently (\\ % | ^ and quotes)' };
  const at = auth.split('@');
  if (at.length > 2) return { problem: 'the host part has more than one @' };
  const hp = at[at.length - 1];
  if (hp.startsWith('[')) {
    const close = hp.indexOf(']');
    const v6 = close < 0 || !/^(?::\d*)?$/.test(hp.slice(close + 1)) ? null : parseIPv6(hp.slice(1, close));
    return v6 ? { host: formatIPv6(v6) } : { problem: 'not a valid IPv6 address' };
  }
  if (/[[\]]/.test(hp)) return { problem: 'a curl glob in the host expands to hosts the guard never sees' };
  const colon = hp.indexOf(':');
  if (colon >= 0 && !/^\d*$/.test(hp.slice(colon + 1))) return { problem: 'not a valid port' };
  return hostName(colon >= 0 ? hp.slice(0, colon) : hp);
}

function hostName(raw) {
  let host = raw.toLowerCase();
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (!host) return { problem: 'there is no host' };
  const labels = host.split('.');
  // WHATWG URL: a host whose last label is a number is an IPv4 address (decimal, octal or hex parts)
  if (/^(?:\d+|0x[0-9a-f]*)$/.test(labels[labels.length - 1])) {
    const ip = parseIPv4(host);
    return ip ? { host: ip } : { problem: 'not a valid IPv4 address' };
  }
  if (host.length > 253 || !labels.every(l => LABEL.test(l))) return { problem: 'not a valid host name' };
  return { host };
}

function ipv4Part(p) {
  if (p === '') return null;
  let radix = 10;
  if (/^0x/i.test(p)) { p = p.slice(2); radix = 16; } else if (p.length > 1 && p[0] === '0') { p = p.slice(1); radix = 8; }
  if (p === '') return 0;
  const digits = radix === 16 ? /^[0-9a-f]+$/i : radix === 8 ? /^[0-7]+$/ : /^\d+$/;
  return digits.test(p) ? parseInt(p, radix) : null;
}

function parseIPv4(s) {
  const parts = s.split('.');
  if (parts.length > 4) return null;
  const nums = parts.map(ipv4Part);
  if (nums.includes(null)) return null;
  const last = nums.pop();
  if (nums.some(n => n > 255) || last >= 256 ** (4 - nums.length)) return null;
  let v = last;
  nums.forEach((n, i) => { v += n * 256 ** (3 - i); });
  return [Math.floor(v / 16777216) % 256, Math.floor(v / 65536) % 256, Math.floor(v / 256) % 256, v % 256].join('.');
}

// The WHATWG URL IPv6 parser: eight 16-bit pieces, or null.
function parseIPv6(s) {
  const a = [0, 0, 0, 0, 0, 0, 0, 0];
  let piece = 0, compress = null, i = 0;
  const hex = c => c !== undefined && /[0-9a-f]/i.test(c);
  const digit = c => c !== undefined && /[0-9]/.test(c);
  if (s[i] === ':') {
    if (s[i + 1] !== ':') return null;
    i += 2; piece = 1; compress = 1;
  }
  while (i < s.length) {
    if (piece === 8) return null;
    if (s[i] === ':') {
      if (compress !== null) return null;
      i++; piece++; compress = piece;
      continue;
    }
    let value = 0, length = 0;
    while (length < 4 && hex(s[i])) { value = value * 16 + parseInt(s[i], 16); i++; length++; }
    if (s[i] === '.') {
      if (length === 0) return null;
      i -= length;
      if (piece > 6) return null;
      let seen = 0;
      while (i < s.length) {
        let v4 = null;
        if (seen > 0) {
          if (s[i] === '.' && seen < 4) i++;
          else return null;
        }
        if (!digit(s[i])) return null;
        while (digit(s[i])) {
          const n = Number(s[i]);
          if (v4 === null) v4 = n;
          else if (v4 === 0) return null;
          else v4 = v4 * 10 + n;
          if (v4 > 255) return null;
          i++;
        }
        a[piece] = a[piece] * 256 + v4;
        seen++;
        if (seen === 2 || seen === 4) piece++;
      }
      if (seen !== 4) return null;
      break;
    } else if (s[i] === ':') {
      i++;
      if (i >= s.length) return null;
    } else if (i < s.length) return null;
    a[piece] = value;
    piece++;
  }
  if (compress !== null) {
    let swaps = piece - compress;
    piece = 7;
    while (piece !== 0 && swaps > 0) {
      [a[piece], a[compress + swaps - 1]] = [a[compress + swaps - 1], a[piece]];
      piece--; swaps--;
    }
  } else if (piece !== 8) return null;
  return a;
}

// RFC 5952 text. An IPv4-mapped address (::ffff:a.b.c.d) is the IPv4 address it connects to.
function formatIPv6(a) {
  if (a.slice(0, 5).every(x => x === 0) && a[5] === 0xffff) {
    return [a[6] >> 8, a[6] & 255, a[7] >> 8, a[7] & 255].join('.');
  }
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (a[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && a[j] === 0) j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = a.map(x => x.toString(16));
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

const v6ToBig = a => a.reduce((acc, x) => (acc << 16n) | BigInt(x), 0n);
const v4ToInt = h => h.split('.').reduce((acc, x) => acc * 256 + Number(x), 0);

function isPublicSuffix(host) {
  const labels = host.split('.');
  return labels.length === 1 || (labels.length === 2 && SLD.has(labels[0]) && labels[1].length === 2);
}

function unicodeProblem(rule) {
  const host = rule.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/?#:]/)[0];
  const wild = host.startsWith('*.');
  let ascii = '';
  try { ascii = domainToASCII(wild ? host.slice(2) : host); } catch { ascii = ''; }
  return ascii && /^[\x21-\x7e]+$/.test(ascii)
    ? `not ASCII: write it in punycode, as ${wild ? '*.' : ''}${ascii}`
    : 'not ASCII: write the host in punycode (xn--...)';
}

function cidrRule(ipText, bits) {
  if (ipText.includes(':')) {
    const v6 = parseIPv6(ipText);
    if (!v6 || bits > 128) return { problem: 'not a valid IPv6 CIDR' };
    if (bits >= 96 && a6IsMapped(v6)) return cidr4(v6[6] * 65536 + v6[7], bits - 96);
    const all = (1n << 128n) - 1n;
    const mask = bits === 0 ? 0n : all ^ ((1n << BigInt(128 - bits)) - 1n);
    return { rule: { kind: 'cidr6', net: v6ToBig(v6) & mask, mask, bits } };
  }
  if (!DOTTED_QUAD.test(ipText) || bits > 32) return { problem: 'not a valid IPv4 CIDR (write a.b.c.d/n)' };
  return cidr4(v4ToInt(ipText), bits);
}
const a6IsMapped = v6 => v6.slice(0, 5).every(x => x === 0) && v6[5] === 0xffff;
function cidr4(n, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { rule: { kind: 'cidr4', net: (n & mask) >>> 0, mask, bits } };
}

/** A rule as scope.json text, in the one form canonRule reads back as the same rule. */
export function ruleText(rule) {
  switch (rule.kind) {
    case 'wild':
      return `*.${rule.base}`;
    case 'glob':
      return rule.pattern;
    case 'cidr4':
      return `${[rule.net >>> 24, (rule.net >>> 16) & 255, (rule.net >>> 8) & 255, rule.net & 255].join('.')}/${rule.bits}`;
    case 'cidr6': {
      const pieces = [];
      for (let i = 7; i >= 0; i--) pieces.push(Number((rule.net >> BigInt(16 * i)) & 0xffffn));
      return `${formatIPv6(pieces)}/${rule.bits}`;
    }
    default:
      return rule.value;
  }
}

function wildRule(s, side) {
  if (s.startsWith('*.') && !s.slice(2).includes('*')) {
    const base = hostName(s.slice(2));
    if (base.problem || isIP(base.host)) return { problem: 'a wildcard needs a domain after *.' };
    if (side !== 'out' && isPublicSuffix(base.host)) return { problem: `*.${base.host} would cover a whole TLD or public suffix` };
    return { rule: { kind: 'wild', base: base.host } };
  }
  if (side !== 'out') {
    return { problem: 'a * anywhere but the start (*.domain) can only exclude: put it in outOfScope or denyUnlisted' };
  }
  if (!/^[a-z0-9.*_-]+$/.test(s) || !/[a-z0-9]/.test(s.replace(/\*/g, ''))) return { problem: 'a pattern that would match every host' };
  return { rule: { kind: 'glob', pattern: s } };
}

/** One scope.json entry → the rule the guard enforces, or why it can't be enforced exactly. */
export function canonRule(rule, side = 'in') {
  if (typeof rule !== 'string') return { problem: 'not a string' };
  const r = stripWs(stripWs(rule).replace(/[,;]+$/, '').replace(/^[`"']+|[`"']+$/g, '').replace(/[,;]+$/, ''));
  if (!r) return { problem: 'empty' };
  if (/\s/.test(r)) return { problem: 'free text, not a host, wildcard, IP or CIDR' };
  if (/[^\x21-\x7e]/.test(r)) return { problem: unicodeProblem(r) };
  let s = r.toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  const cidr = /^((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]*:[0-9a-f:.]*)\/(\d{1,3})$/.exec(s);
  if (cidr) return cidrRule(cidr[1], Number(cidr[2]));
  const cut = s.search(/[/?#]/);
  if (cut >= 0) s = s.slice(0, cut); // scope is per host: a path can't be enforced, the host is
  const at = s.split('@');
  if (at.length > 2) return { problem: 'more than one @' };
  s = at[at.length - 1];
  if (s.startsWith('[') || (s.match(/:/g) || []).length > 1) {
    const close = s.indexOf(']');
    const inner = s.startsWith('[') ? (close < 0 || !/^(?::\d*)?$/.test(s.slice(close + 1)) ? null : s.slice(1, close)) : s;
    const v6 = inner === null ? null : parseIPv6(inner);
    return v6 ? { rule: { kind: 'ip', value: formatIPv6(v6) } } : { problem: 'not a valid IPv6 address' };
  }
  const colon = s.indexOf(':');
  if (colon >= 0) {
    if (!/^\d*$/.test(s.slice(colon + 1))) return { problem: 'not a valid port' };
    s = s.slice(0, colon);
  }
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (s.includes('*')) return wildRule(s, side);
  if (/[^a-z0-9._-]/.test(s)) return { problem: 'not a host, wildcard, IP or CIDR' };
  const labels = s.split('.');
  if (/^(?:\d+|0x[0-9a-f]*)$/.test(labels[labels.length - 1])) {
    return DOTTED_QUAD.test(s) ? { rule: { kind: 'ip', value: s } } : { problem: 'write an IPv4 address as plain dotted decimal (a.b.c.d)' };
  }
  const h = hostName(s);
  return h.problem ? h : { rule: { kind: 'host', value: h.host } };
}

const globCache = new Map();
function ruleMatches(rule, host) {
  switch (rule.kind) {
    case 'host':
    case 'ip':
      return host === rule.value;
    case 'wild':
      return host.endsWith(`.${rule.base}`);
    case 'glob': {
      let re = globCache.get(rule.pattern);
      if (!re) {
        re = new RegExp(`^${rule.pattern.replace(/[.]/g, '\\.').replace(/\*/g, '[a-z0-9._-]*')}$`);
        globCache.set(rule.pattern, re);
      }
      return re.test(host);
    }
    case 'cidr4':
      return isIPv4(host) && ((v4ToInt(host) & rule.mask) >>> 0) === rule.net;
    case 'cidr6': {
      const v6 = host.includes(':') ? parseIPv6(host) : null;
      return v6 !== null && (v6ToBig(v6) & rule.mask) === rule.net;
    }
    default:
      return false;
  }
}
const matchAny = (host, rules) => rules.some(r => ruleMatches(r, host));

function isLocalIP(host) {
  if (host === '::1') return true;
  if (!isIPv4(host)) return false;
  const n = v4ToInt(host);
  return n >>> 24 === 10 || n >>> 24 === 127 || n >>> 16 === 0xc0a8 || n >>> 20 === 0xac1;
}

const DEFAULT_ALLOW_RULES = DEFAULT_ALLOW.map(r => canonRule(r, 'allow').rule);

/** Parsed scope.json → the rules and every reason the file can't be enforced as written. */
export function compileScope(raw) {
  const c = { inScope: [], outOfScope: [], denyUnlisted: [], allow: [...DEFAULT_ALLOW_RULES], errors: [], active: true, off: false, raw: {} };
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    c.errors.push('notes/scope.json must be a JSON object');
    return c;
  }
  c.raw = raw;
  for (const k of BOOL_FIELDS) {
    if (raw[k] != null && typeof raw[k] !== 'boolean') c.errors.push(`${k} must be true or false, not ${JSON.stringify(raw[k])}`);
  }
  for (const k of STRING_FIELDS) if (raw[k] != null && typeof raw[k] !== 'string') c.errors.push(`${k} must be a string`);
  const hdrs = raw.requiredHeaders;
  if (hdrs != null && !(Array.isArray(hdrs) && hdrs.every(h => typeof h === 'string'))) c.errors.push('requiredHeaders must be a list of strings');
  for (const [key, side] of Object.entries(RULE_LISTS)) {
    const list = raw[key];
    if (list == null) continue;
    if (!Array.isArray(list)) { c.errors.push(`${key} must be a list`); continue; }
    for (const item of list) {
      const res = canonRule(item, side);
      if (res.problem) c.errors.push(`${key} entry ${JSON.stringify(item)}: ${res.problem}`);
      else (side === 'allow' ? c.allow : c[key]).push(res.rule);
    }
  }
  c.off = raw.enforce === false;
  const ins = raw.inScope;
  c.active = !c.off && ins != null && !(Array.isArray(ins) && ins.length === 0);
  return c;
}

/** OOS | IN_SCOPE | OOS_UNLISTED | ALLOWED | UNKNOWN for a canonical host. */
export function classify(host, c) {
  if (matchAny(host, c.outOfScope)) return 'OOS';
  if (matchAny(host, c.inScope)) return 'IN_SCOPE';
  if (matchAny(host, c.denyUnlisted)) return 'OOS_UNLISTED';
  if (matchAny(host, c.allow) || isLocalIP(host)) return 'ALLOWED';
  return 'UNKNOWN';
}

// ZeroProtocol-style scope confirmation. Canonicalize the confirmed scope sets (lowercased, unique,
// ordinal-sorted) and SHA-256 them. `bountyproof scope confirm` (and tools/scripts/confirm-scope.ps1)
// compute the same hash and write it to scope.confirmedScope. Any edit to inScope/outOfScope/denyUnlisted
// makes the stored hash stale, which — when requireConfirm is true — re-blocks live in-scope testing until
// a human re-confirms.
function canonList(arr) {
  const set = new Set((Array.isArray(arr) ? arr : []).map(x => String(x).trim().toLowerCase()).filter(Boolean));
  return [...set].sort().join(',');
}
export function scopeHash(scope) {
  const s = `inScope=${canonList(scope.inScope)}|outOfScope=${canonList(scope.outOfScope)}|denyUnlisted=${canonList(scope.denyUnlisted)}`;
  return crypto.createHash('sha256').update(s).digest('hex');
}

// ------------------------------------------------------------------------------------------------
// Commands
// ------------------------------------------------------------------------------------------------

const NET_TOOLS = new Set([
  'curl', 'wget', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'httpx', 'ffuf',
  'nuclei', 'sqlmap', 'nmap', 'gobuster', 'feroxbuster', 'dirsearch', 'katana', 'arjun', 'dalfox',
  'python', 'node', 'openssl', 'ncat', 'nc',
]);
const NET_HINT = /\b(curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm|httpx|ffuf|nuclei|sqlmap|nmap|gobuster|feroxbuster|dirsearch|katana|arjun|dalfox|python[\d.]*|py|node|openssl|ncat|nc)\b/i;
// Confirming the scope is the human's step, so the agent can't run it (CLI or PowerShell script).
// Reading or searching for it is fine.
const CONFIRM_RE = /\bscope\s+confirm\b|confirm-scope\.ps1/i;
const READERS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'type', 'get-content', 'gc', 'grep', 'rg', 'findstr', 'select-string',
  'sls', 'sed', 'awk', 'wc', 'ls', 'dir', 'echo', 'printf', 'write-output', 'write-host', 'git', 'diff',
]);
// Commands that only read the files they name (for the scope.json write check).
const FILE_READERS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'type', 'get-content', 'gc', 'grep', 'egrep', 'rg', 'findstr',
  'select-string', 'sls', 'wc', 'ls', 'dir', 'jq', 'diff', 'fc', 'file', 'stat', 'bountyproof', 'code',
]);
const GIT_READS = new Set(['diff', 'log', 'show', 'status', 'add', 'blame', 'grep', 'ls-files']);
const URL_RE = /\b(?:https?|wss?):\/\/[^\s'"<>`)\]}]+/gi;
const HOST_RE = /(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?![\w-])/gi;
// a lookalike written in a script: an IDN, fullwidth or percent-encoded host, or a backslash trick
const LOOKALIKE = /[^\x00-\x7e]|%[0-9a-f]{2}|\\/i;
const HOST_HDR_RE = /(?:^|[\s{;'"])host['"]?\s*[:=]\s*['"]?([^\s'";},]+)/gim;

// Every curl option that takes a value (curl --help all, 8.15 and 8.23); every other argument is a URL.
const CURL_VALUE_LONG = new Set([
  'abstract-unix-socket', 'alt-svc', 'aws-sigv4', 'cacert', 'capath', 'cert', 'cert-type', 'ciphers',
  'config', 'connect-timeout', 'connect-to', 'continue-at', 'cookie', 'cookie-jar', 'create-file-mode',
  'crlfile', 'curves', 'data', 'data-ascii', 'data-binary', 'data-raw', 'data-urlencode', 'delegation',
  'dns-interface', 'dns-ipv4-addr', 'dns-ipv6-addr', 'dns-servers', 'doh-url', 'dump-header', 'ech',
  'egd-file', 'engine', 'etag-compare', 'etag-save', 'expect100-timeout', 'form', 'form-string',
  'ftp-account', 'ftp-alternative-to-user', 'ftp-method', 'ftp-port', 'ftp-ssl-ccc-mode',
  'happy-eyeballs-timeout-ms', 'haproxy-clientip', 'header', 'help', 'hostpubmd5', 'hostpubsha256', 'hsts',
  'interface', 'ip-tos', 'ipfs-gateway', 'json', 'keepalive-cnt', 'keepalive-time', 'key', 'key-type',
  'knownhosts', 'krb', 'libcurl', 'limit-rate', 'local-port', 'login-options', 'mail-auth', 'mail-from',
  'mail-rcpt', 'max-filesize', 'max-redirs', 'max-time', 'netrc-file', 'noproxy', 'oauth2-bearer', 'output',
  'output-dir', 'parallel-max', 'parallel-max-host', 'pass', 'pinnedpubkey', 'preproxy', 'proto',
  'proto-default', 'proto-redir', 'proxy', 'proxy-cacert', 'proxy-capath', 'proxy-cert', 'proxy-cert-type',
  'proxy-ciphers', 'proxy-crlfile', 'proxy-header', 'proxy-key', 'proxy-key-type', 'proxy-pass',
  'proxy-pinnedpubkey', 'proxy-service-name', 'proxy-tls13-ciphers', 'proxy-tlsauthtype',
  'proxy-tlspassword', 'proxy-tlsuser', 'proxy-user', 'proxy1.0', 'pubkey', 'quote', 'random-file', 'range',
  'rate', 'referer', 'request', 'request-target', 'resolve', 'retry', 'retry-delay', 'retry-max-time',
  'sasl-authzid', 'service-name', 'sigalgs', 'socks4', 'socks4a', 'socks5', 'socks5-gssapi-service',
  'socks5-hostname', 'speed-limit', 'speed-time', 'ssl-sessions', 'stderr', 'telnet-option', 'tftp-blksize',
  'time-cond', 'tls-max', 'tls13-ciphers', 'tlsauthtype', 'tlspassword', 'tlsuser', 'trace', 'trace-ascii',
  'trace-config', 'trace-ids', 'unix-socket', 'upload-file', 'upload-flags', 'url', 'url-query', 'user',
  'user-agent', 'variable', 'vlan-priority', 'write-out',
]);
const CURL_VALUE_SHORT = new Set('ACDEFHKPQTUXYbcdehmortuwxyz'.split(''));
const CURL_PROXY = new Set(['x', 'proxy', 'preproxy', 'proxy1.0', 'socks4', 'socks4a', 'socks5', 'socks5-hostname']);
const CURL_BODY = new Set(['d', 'F', 'T', 'data', 'data-raw', 'data-binary', 'data-urlencode',
  'data-ascii', 'json', 'form', 'form-string', 'upload-file']);
const WGET_VALUE_SHORT = new Set('oaeOPUtTwQlARDIXBi'.split(''));
const WGET_VALUE_LONG = new Set([
  'output-file', 'append-output', 'execute', 'config', 'input-file', 'base', 'bind-address', 'tries',
  'output-document', 'wait', 'waitretry', 'quota', 'limit-rate', 'timeout', 'dns-timeout', 'connect-timeout',
  'read-timeout', 'directory-prefix', 'cut-dirs', 'user', 'password', 'http-user', 'http-password',
  'ftp-user', 'ftp-password', 'header', 'max-redirect', 'proxy-user', 'proxy-password', 'referer',
  'user-agent', 'load-cookies', 'save-cookies', 'post-data', 'post-file', 'method', 'body-data', 'body-file',
  'certificate', 'certificate-type', 'private-key', 'private-key-type', 'ca-certificate', 'ca-directory',
  'level', 'accept', 'reject', 'accept-regex', 'reject-regex', 'domains', 'exclude-domains', 'follow-tags',
  'ignore-tags', 'include-directories', 'exclude-directories', 'restrict-file-names', 'default-page',
  'secure-protocol', 'local-encoding', 'remote-encoding',
]);
const PS_VAL = new Set(['uri', 'method', 'body', 'headers', 'useragent', 'outfile', 'contenttype',
  'sessionvariable', 'websession', 'timeoutsec', 'maximumredirection', 'proxy', 'proxycredential',
  'credential', 'infile', 'form', 'certificate', 'certificatethumbprint', 'transferencoding',
  'maximumretrycount', 'retryintervalsec', 'authentication', 'token', 'custommethod', 'httpversion']);
// Probers and scanners: which flags name a target, a file of targets or a raw request; which follow
// redirects to any host; and whether they read targets from stdin.
const SCANNERS = {
  httpx: { target: ['u', 'target'], list: ['l', 'list'], follow: ['fr', 'follow-redirects'], stdin: true },
  nuclei: { target: ['u', 'target'], list: ['l', 'list'], follow: ['fr', 'follow-redirects'], stdin: true },
  katana: { target: ['u', 'list'], stdin: true, crawl: true },
  ffuf: { target: ['u'], follow: ['r'] },
  sqlmap: { target: ['u', 'url'], list: ['m'], request: ['r'] },
  dalfox: { stdin: true },
  arjun: { target: ['u'], list: ['i'] },
  gobuster: { target: ['u', 'url'], follow: ['r', 'follow-redirect'] },
  feroxbuster: { target: ['u', 'url'], follow: ['r', 'redirects'], stdin: true },
  dirsearch: { target: ['u', 'url'], list: ['l', 'url-file'], follow: ['F', 'follow-redirects'], stdin: true },
  openssl: { target: ['connect', 'servername'] },
  nmap: { list: ['iL'], positional: true },
  nc: { positional: true },
  ncat: { positional: true },
};
const NMAP_VALUE = new Set(['p', 'oN', 'oX', 'oG', 'oA', 'oS', 'e', 'D', 'S', 'g', 'sI', 'script', 'script-args',
  'exclude', 'excludefile', 'top-ports', 'max-rate', 'min-rate', 'max-retries', 'host-timeout', 'scan-delay',
  'dns-servers', 'source-port', 'data-length', 'ttl', 'datadir', 'stylesheet', 'max-parallelism',
  'min-parallelism', 'version-intensity', 'mtu', 'spoof-mac', 'proxies', 'w', 'i', 'c', 'q', 'x', 'X']);
const NC_VALUE = new Set('pswecqiIOTxX'.split(''));
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const HTTP_CLIENTS = new Set(['curl', 'wget', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm']);
const CHROME = 'mcp__claude-in-chrome__';
const CHROME_PRESS = new Set(['left_click', 'double_click', 'triple_click', 'key']);
const SUBMIT_RE = /\b(submit\w*|send(s|ing)?|publish\w*|env[ií]a\w*)\b/i;
const LIST_MAX_BYTES = 2 * 1024 * 1024;
const LIST_MAX_LINES = 20000;

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
// Unquoted | ; & ( ) newline split segments (`piped` marks one fed by a single |); > and < mark the
// next token as a redirect target, and an fd number glued to them (2>, *>) is dropped.
function segments(cmd, ps) {
  const esc = ps ? '`' : '\\';
  const segs = [{ tokens: [], redirects: [], piped: false }];
  let cur = '', quote = null, has = false, redirect = false;
  const push = () => {
    if (has) {
      const seg = segs[segs.length - 1];
      (redirect ? seg.redirects : seg.tokens).push(cur);
      redirect = false;
    }
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
    if ('|;&()\n'.includes(c)) {
      push();
      segs.push({ tokens: [], redirects: [], piped: c === '|' && cmd[i + 1] !== '|' && cmd[i - 1] !== '|' });
      continue;
    }
    if (c === '>' || c === '<') {
      if (has && /^(?:\d+|\*)$/.test(cur)) { cur = ''; has = false; }
      push();
      redirect = true;
      while (cmd[i + 1] === '>' || cmd[i + 1] === '&') i++;
      continue;
    }
    cur += c; has = true;
  }
  push();
  return segs.filter(s => s.tokens.length || s.redirects.length);
}

function toolName(tok) {
  let base = tok.replace(/^.*[\\/]/, '').toLowerCase();
  if (base.endsWith('.exe')) base = base.slice(0, -4);
  return /^python[\d.]*$|^py$/.test(base) ? 'python' : base;
}

function confirmsScope(cmd, ps) {
  if (!CONFIRM_RE.test(cmd)) return false;
  for (const { tokens: seg } of segments(cmd, ps)) {
    let i = 0;
    while (i < seg.length && (seg[i] === '&' || seg[i] === '.' || /^[A-Za-z_]\w*=/.test(seg[i]))) i++;
    if (i >= seg.length || READERS.has(toolName(seg[i]))) continue;
    const words = seg.slice(i).map(t => t.toLowerCase());
    if (words.some(w => w.endsWith('confirm-scope.ps1') || /\bscope\s+confirm\b/.test(w))) return true;
    if (words.some((w, j) => w === 'scope' && words[j + 1] === 'confirm')) return true;
  }
  return false;
}

function newReq(tool) {
  return { tool, dests: [], mentions: [], lists: [], requests: [], cidrs: [], ua: '', headers: [], method: '',
    body: '', hasBody: false, getFlag: false, follow: '', unseen: '', crawl: '', info: false };
}

// --resolve [+]host:port:addr[,addr]... → the addresses the connection really goes to
function resolveAddrs(v) {
  if (v.startsWith('-')) return [];
  const s = v.replace(/^\+/, '');
  const first = s.indexOf(':');
  const second = first < 0 ? -1 : s.indexOf(':', first + 1);
  if (second < 0) return [v];
  return s.slice(second + 1).split(',').map(x => x.trim()).filter(Boolean);
}

// --connect-to HOST1:PORT1:HOST2:PORT2 → HOST2 (empty = same host, another port)
function connectToHost(v) {
  const m = /^(\[[^\]]*\]|[^:]*):([^:]*):(\[[^\]]*\]|[^:]*):(.*)$/.exec(v);
  if (!m) return v;
  return m[3] || null;
}

function parseCurl(args) {
  const r = newReq('curl');
  let location = false, maxRedirs = null;
  const take = (name, val) => {
    if (name === 'url' || name === 'doh-url' || CURL_PROXY.has(name)) r.dests.push(val); // a proxy gets the bytes too
    else if (name === 'resolve') r.dests.push(...resolveAddrs(val));
    else if (name === 'connect-to') { const h = connectToHost(val); if (h) r.dests.push(h); }
    else if (name === 'user-agent' || name === 'A') r.ua = val;
    else if (name === 'header' || name === 'H') r.headers.push(val);
    else if (name === 'request' || name === 'X') r.method = val.toUpperCase();
    else if (name === 'config' || name === 'K') r.unseen = 'curl -K reads its URLs from a config file the guard does not open: put the URL in the command';
    else if (name === 'max-redirs') maxRedirs = val.trim();
    else if (name === 'help' || name === 'h') r.info = true;
    if (CURL_BODY.has(name)) { r.hasBody = true; r.body += ` ${val}`; }
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--') && a.length > 2) {
      let [name, val] = a.slice(2).split(/=(.*)/s);
      name = name.replace(/^expand-/, '');
      if (CURL_VALUE_LONG.has(name)) {
        if (val === undefined) val = args[++i] ?? '';
        take(name, val);
      } else if (name === 'location' || name === 'location-trusted') location = true;
      else if (name === 'get') r.getFlag = true;
      else if (name === 'version' || name === 'manual') r.info = true;
      continue;
    }
    if (a.startsWith('-') && a.length > 1) {
      const chars = a.slice(1);
      for (let j = 0; j < chars.length; j++) {
        const ch = chars[j];
        if (ch === 'L') location = true;
        else if (ch === 'G') r.getFlag = true;
        else if (ch === 'V' || ch === 'M') r.info = true;
        if (!CURL_VALUE_SHORT.has(ch)) continue;
        take(ch, j + 1 < chars.length ? chars.slice(j + 1) : (args[++i] ?? ''));
        break;
      }
      continue;
    }
    r.dests.push(a); // curl reads every other argument as a URL
  }
  if (location && maxRedirs !== '0') {
    r.follow = 'curl -L follows redirects to hosts the guard never sees (an in-scope host can redirect anywhere). Drop -L (or add --max-redirs 0), read the Location header with -i, and request that URL explicitly so the guard checks it.';
  }
  if (!r.method) r.method = r.hasBody && !r.getFlag ? 'POST' : 'GET';
  if (!r.dests.length && !r.info && !r.unseen) {
    r.unseen = 'curl has no URL the guard can read (it comes from a variable, a pipe or xargs?): write the URL in the command';
  }
  return r;
}

function parseWget(args) {
  const r = newReq('wget');
  let maxRedirect = null;
  const take = (name, val) => {
    if (name === 'user-agent' || name === 'U') r.ua = val;
    else if (name === 'header') r.headers.push(val);
    else if (name === 'method') r.method = val.toUpperCase();
    else if (name === 'max-redirect') maxRedirect = val.trim();
    else if (name === 'input-file' || name === 'i') r.lists.push(val);
    if (['post-data', 'post-file', 'body-data', 'body-file'].includes(name)) { r.hasBody = true; r.body += ` ${val}`; }
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--') && a.length > 2) {
      let [name, val] = a.slice(2).split(/=(.*)/s);
      if (WGET_VALUE_LONG.has(name)) {
        if (val === undefined) val = args[++i] ?? '';
        take(name, val);
      } else if (name === 'span-hosts') r.crawl = 'wget --span-hosts follows links to any host: drop it';
      else if (name === 'version' || name === 'help') r.info = true;
      continue;
    }
    if (a.startsWith('-') && a.length > 1) {
      const chars = a.slice(1);
      for (let j = 0; j < chars.length; j++) {
        const ch = chars[j];
        if (ch === 'H') r.crawl = 'wget -H (span hosts) follows links to any host: drop it';
        else if (ch === 'V' || ch === 'h') r.info = true;
        if (!WGET_VALUE_SHORT.has(ch)) continue;
        take(ch, j + 1 < chars.length ? chars.slice(j + 1) : (args[++i] ?? ''));
        break;
      }
      continue;
    }
    r.dests.push(a);
  }
  if (maxRedirect !== '0') {
    r.follow = 'wget follows redirects by default, to hosts the guard never sees. Add --max-redirect=0 and request the Location explicitly.';
  }
  if (!r.method) r.method = r.hasBody ? 'POST' : 'GET';
  if (!r.dests.length && !r.lists.length && !r.info) r.unseen = 'wget has no URL the guard can read: write the URL in the command';
  return r;
}

function parseInvoke(tool, args) {
  const r = newReq(tool);
  let maxRedir = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const m = /^-([a-z][a-z0-9]*)(?::(.*))?$/is.exec(a);
    if (m) {
      const name = m[1].toLowerCase();
      if (!PS_VAL.has(name)) continue;
      const val = m[2] !== undefined && m[2] !== '' ? m[2] : (args[++i] ?? '');
      if (name === 'uri' || name === 'proxy') r.dests.push(val);
      else if (name === 'method' || name === 'custommethod') r.method = val.toUpperCase();
      else if (name === 'useragent') r.ua = val;
      else if (name === 'headers') r.headers.push(val);
      else if (name === 'maximumredirection') maxRedir = val.trim();
      else if (['body', 'infile', 'form'].includes(name)) { r.hasBody = true; r.body += ` ${val}`; }
      continue;
    }
    r.dests.push(a);
  }
  if (maxRedir !== '0') {
    r.follow = `${tool} follows redirects by default, to hosts the guard never sees. Add -MaximumRedirection 0 and request the Location explicitly.`;
  }
  if (!r.method) r.method = 'GET';
  if (!r.dests.length) r.unseen = `${tool} has no URL the guard can read: write the URL in the command`;
  return r;
}

const looksLikeTarget = t => /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/.test(t) || /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(t) || /^\[?[0-9a-f:]+\]?$/i.test(t);

function parseScanner(tool, args, piped, cwd) {
  const spec = SCANNERS[tool];
  const r = newReq(tool);
  const text = args.join(' ');
  r.dests.push(...(text.match(URL_RE) || [])); // every URL in a scanner's arguments is a destination
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const m = /^--?([A-Za-z][\w.-]*)(?:=(.*))?$/s.exec(a);
    if (m) {
      const name = m[1];
      const val = () => (m[2] !== undefined ? m[2] : (args[++i] ?? ''));
      if (spec.target?.includes(name)) {
        const v = val();
        if (!SCHEME.test(v)) (isFile(v, cwd) ? r.lists : r.dests).push(v);
      } else if (spec.list?.includes(name)) r.lists.push(val());
      else if (spec.request?.includes(name)) r.requests.push(val());
      else if (spec.follow?.includes(name)) r.follow = `${tool} -${name} follows redirects to any host, which the guard never sees: drop it (or use the same-host variant).`;
      else if (tool === 'nmap' && NMAP_VALUE.has(name)) i++;
      else if ((tool === 'nc' || tool === 'ncat') && name.length >= 1 && /^[a-z]+$/i.test(name)) {
        if (NC_VALUE.has(name[name.length - 1]) && m[2] === undefined) i++;
      } else if (/^(?:h|help|version|V|update.*|ut|up)$/.test(name)) r.info = true;
      continue;
    }
    if (tool === 'dalfox' && a === 'file' && i === 0) { r.lists.push(args[++i] ?? ''); continue; }
    if (spec.positional && !SCHEME.test(a)) {
      if (/^\d+$/.test(a) && (tool === 'nc' || tool === 'ncat') && r.dests.length) continue; // the port after the host
      if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(a)) r.cidrs.push(a);
      else if (/[,*]|\d-\d/.test(a) && /^[\d.,*/-]+$/.test(a)) r.unseen = `${tool} range "${a}": write a CIDR or each host so the guard can check them`;
      else if (looksLikeTarget(a) || /^\d+$/.test(a)) r.dests.push(a);
    }
  }
  if (spec.crawl && !/(?:^|\s)-(?:fs|field-scope)[=\s]+fqdn\b/.test(text)) {
    r.crawl = `${tool} follows links to every host under the root domain by default: add -fs fqdn so it stays on the host you named`;
  }
  if (piped && spec.stdin && !r.dests.length && !r.lists.length) {
    r.unseen = `${tool} reads its targets from a pipe the guard can't see: write them to a file and pass it with -l <file> (the guard reads the file)`;
  }
  const ua = /(?:--user-agent|-U|-A|User-Agent:)\s*=?\s*("[^"]*"|'[^']*'|[^\s]+)/i.exec(text);
  if (ua) r.ua = ua[1];
  r.headers.push(text);
  const mm = /(?:-X\s*|--request\s+|-method\s+|--method[=\s]+)(post|put|patch|delete)\b/i.exec(text);
  r.method = mm ? mm[1].toUpperCase() : 'GET';
  r.body = text;
  return r;
}

// Inline python / node: the guard sees code, not runtime values, so a host there is only a mention.
function parseCode(tool, args) {
  const r = newReq(tool);
  const text = args.join(' ');
  r.mentions.push(...(text.match(URL_RE) || []));
  for (const m of text.matchAll(HOST_RE)) r.mentions.push(m[1]);
  const ua = /(?:--user-agent|-U|-A|User-Agent:|['"]User-Agent['"]\s*:)\s*=?\s*("[^"]*"|'[^']*'|[^\s]+)/i.exec(text);
  if (ua) r.ua = ua[1];
  r.headers.push(text);
  const mm = /(?:method\s*[:=]\s*['"]?|\.)(post|put|patch|delete)\b/i.exec(text);
  r.method = mm ? mm[1].toUpperCase() : 'GET';
  r.body = text;
  return r;
}

function parseTool(tool, args, piped, cwd) {
  if (tool === 'curl') return parseCurl(args);
  if (tool === 'wget') return parseWget(args);
  if (['invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm'].includes(tool)) return parseInvoke(tool, args);
  if (SCANNERS[tool]) return parseScanner(tool, args, piped, cwd);
  return parseCode(tool, args);
}

function isFile(p, cwd) {
  try { return fs.statSync(path.resolve(cwd, p)).isFile(); } catch { return false; }
}

// A file of targets (httpx -l, nuclei -l, nmap -iL...): the guard reads it and checks every line.
function readTargets(file, cwd) {
  if (!file || file === '-') return { problem: 'it reads its targets from stdin, which the guard can\'t see: pass a file' };
  let text;
  try {
    const p = path.resolve(cwd, file);
    if (fs.statSync(p).size > LIST_MAX_BYTES) return { problem: `${file} is too big for the guard to check: split it` };
    text = fs.readFileSync(p, 'utf8');
  } catch {
    return { problem: `the guard can't read the target list ${file}` };
  }
  const items = text.replace(/^﻿/, '').split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#')).map(l => l.split(/\s+/)[0]);
  return items.length > LIST_MAX_LINES ? { problem: `${file} has more than ${LIST_MAX_LINES} targets: split it` } : { items };
}

// A raw request file (sqlmap -r): its Host header is the destination.
function readRequestHost(file, cwd) {
  try {
    const text = fs.readFileSync(path.resolve(cwd, file), 'utf8');
    const m = /^host\s*:\s*(\S+)/im.exec(text);
    return m ? { host: m[1] } : { problem: `${file} has no Host header` };
  } catch {
    return { problem: `the guard can't read the request file ${file}` };
  }
}

function cidrCovered(text, c) {
  const res = canonRule(text, 'in');
  if (!res.rule) return false;
  const { net, mask } = res.rule;
  const size = (~mask >>> 0) + 1;
  const inside = c.inScope.some(r => r.kind === 'cidr4' && (r.mask >>> 0) <= (mask >>> 0) && ((net & r.mask) >>> 0) === r.net);
  const touchesOos = c.outOfScope.some(r => (r.kind === 'ip' && isIPv4(r.value) && v4ToInt(r.value) >= net && v4ToInt(r.value) < net + size)
    || (r.kind === 'cidr4' && ((r.net & mask) >>> 0 === net || (net & r.mask) >>> 0 === r.net)));
  return inside && !touchesOos;
}

// Claude in Chrome tool calls as {name, input}; browser_batch carries several.
function chromeActions(tname, ti) {
  if (tname === `${CHROME}browser_batch`) {
    return (Array.isArray(ti.actions) ? ti.actions : [])
      .map(a => ({ name: String(a?.name || '').replace(CHROME, ''), input: a?.input || {} }));
  }
  return [{ name: tname.slice(CHROME.length), input: ti }];
}

// Pressing submit on the platform's report form is the human's step.
function submitGate(input) {
  const tname = input.tool_name || '';
  if (!tname.startsWith(CHROME)) return null;
  const press = chromeActions(tname, input.tool_input || {}).find(a =>
    a.name === 'computer' && CHROME_PRESS.has(a.input.action) && SUBMIT_RE.test(String(a.input.action_summary || '')));
  if (!press) return null;
  const what = String(press.input.action_summary).slice(0, 200);
  log({ tool: tname, decision: 'ask', reasons: [`possible submit: ${what}`] });
  return out('ask', `[scope-guard] "${what}" looks like sending the report. Pressing submit is your step: deny this and press it yourself in Chrome after reading the form. Allow only if it just opens an empty form.`);
}

// ------------------------------------------------------------------------------------------------
// The scope is the human's: the agent changing it, or the guard, asks first once the scope is live.
// ------------------------------------------------------------------------------------------------

const norm = p => (process.platform === 'win32' ? p.toLowerCase() : p);
const PROTECTED = [
  path.join(projectDir, 'notes', 'scope.json'), path.join(projectDir, '.claude', 'hooks'),
  path.join(projectDir, '.claude', 'settings.json'), path.join(projectDir, '.claude', 'settings.local.json'),
].map(p => norm(path.resolve(p)));

function isProtected(p, cwd) {
  if (!p) return false;
  const s = String(p);
  if (/\s/.test(s.trim())) return false; // a message or a code string, not a path
  if (/(?:^|[\\/])(?:scope\.json|scope-guard\.mjs)$/i.test(s)) return true;
  if (/\.claude[\\/]+settings(?:\.local)?\.json$/i.test(s)) return true;
  const abs = norm(path.resolve(cwd, s));
  return PROTECTED.some(t => abs === t || abs.startsWith(t + path.sep));
}

function changesProtected(input, cwd) {
  const tname = input.tool_name || '';
  const ti = input.tool_input || {};
  if (['Edit', 'Write', 'MultiEdit', 'NotebookEdit'].includes(tname)) return isProtected(ti.file_path || ti.notebook_path, cwd);
  if (tname !== 'Bash' && tname !== 'PowerShell') return false;
  const raw = String(ti.command || '');
  if (!/scope\.json|scope-guard|settings(?:\.local)?\.json/i.test(raw)) return false;
  for (const seg of segments(raw, tname === 'PowerShell')) {
    if (seg.redirects.some(t => isProtected(t, cwd))) return true;
    let i = 0;
    while (i < seg.tokens.length && (seg.tokens[i] === '&' || seg.tokens[i] === '.' || /^[A-Za-z_]\w*=/.test(seg.tokens[i]))) i++;
    const tool = seg.tokens[i] ? toolName(seg.tokens[i]) : '';
    const args = seg.tokens.slice(i + 1);
    if (tool === 'python' || tool === 'node') {
      if (args.some(a => /scope\.json|scope-guard|settings(?:\.local)?\.json/i.test(a) && /write|dump|unlink|remove|rename|truncate|['"][wa]\+?['"]/i.test(a))) return true;
      continue;
    }
    if (FILE_READERS.has(tool) || (tool === 'git' && GIT_READS.has(args[0]))) continue;
    if (args.some(a => isProtected(a, cwd))) return true;
  }
  return false;
}

// ------------------------------------------------------------------------------------------------
// Decisions
// ------------------------------------------------------------------------------------------------

const out = (decision, reason) => ({
  hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason },
});

function invalidState(message) {
  const c = compileScope({});
  c.errors.push(message);
  c.active = true;
  return c;
}

function loadScope() {
  let text;
  try {
    text = fs.readFileSync(SCOPE_FILE, 'utf8');
  } catch (e) {
    return e && (e.code === 'ENOENT' || e.code === 'ENOTDIR') ? null : invalidState(`notes/scope.json can't be read (${e && e.code})`);
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // Windows PowerShell 5.1 writes a BOM
  try {
    return compileScope(JSON.parse(text));
  } catch (e) {
    return invalidState(`notes/scope.json is not valid JSON (${String(e.message).slice(0, 120)})`);
  }
}

const hasDestination = r => r.dests.length || r.lists.length || r.requests.length || r.cidrs.length || r.unseen
  || r.tool === 'browser' || r.tool === 'chrome';

function requestsOf(input, cwd) {
  const tname = input.tool_name || '';
  const ti = input.tool_input || {};
  if (tname.startsWith('mcp__playwright__')) {
    if (!ti.url) return { reqs: [], raw: '' };
    return { reqs: [{ ...newReq('browser'), dests: [String(ti.url)], ua: '(browser)', method: 'GET' }], raw: `${tname} ${ti.url}` };
  }
  if (tname.startsWith(CHROME)) {
    const urls = chromeActions(tname, ti)
      .filter(a => a.name === 'navigate' && a.input.url && !/^(back|forward)$/i.test(String(a.input.url).trim()))
      .map(a => String(a.input.url).trim())
      .map(u => (/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : `https://${u}`)); // the extension defaults to https
    if (!urls.length) return { reqs: [], raw: '' };
    return { reqs: [{ ...newReq('chrome'), dests: urls, ua: '(chrome)', method: 'GET' }], raw: `${tname} ${urls.join(' ')}` };
  }
  const raw = String(ti.command || '');
  if (!NET_HINT.test(raw)) return { reqs: [], raw };
  const reqs = [];
  for (const seg of segments(raw, tname === 'PowerShell')) {
    const idx = seg.tokens.findIndex(t => NET_TOOLS.has(toolName(t)));
    if (idx === -1) continue;
    reqs.push(parseTool(toolName(seg.tokens[idx]), seg.tokens.slice(idx + 1), seg.piped, cwd));
  }
  return { reqs, raw };
}

function decide(input, c, cwd) {
  const tname = input.tool_name || '';
  const { reqs, raw } = requestsOf(input, cwd);
  if (!reqs.length) return null;

  if (c.errors.length) {
    if (!reqs.some(hasDestination)) return null;
    const errs = c.errors.slice(0, 6).join('; ') + (c.errors.length > 6 ? `; and ${c.errors.length - 6} more` : '');
    log({ tool: tname, decision: 'deny', reasons: [`invalid scope.json: ${errs}`], cmd: redact(raw) });
    return out('deny', `[scope-guard] notes/scope.json is invalid, so network commands are blocked until it's fixed: ${errs}. Fix the file (the human confirms the scope again afterwards) and check it with \`bountyproof scope check <url>\`.`);
  }

  const deny = [], ask = [], hosts = [];
  const stale = c.raw.requireConfirm === true && scopeHash(c.raw) !== (c.raw.confirmedScope || '');
  for (const r of reqs) {
    if (r.unseen && !r.info) { deny.push(r.unseen); continue; }
    if (r.crawl) deny.push(r.crawl);
    const explicit = new Map();
    const add = (tok, where) => {
      const h = canonHost(tok);
      if (h.local) return;
      if (h.problem) { deny.push(`Can't tell which host ${where || JSON.stringify(tok)} goes to: ${h.problem}.`); return; }
      if (!explicit.has(h.host)) explicit.set(h.host, tok);
    };
    r.dests.forEach(t => add(t));
    // A Host: header override points the request at another vhost
    if (HTTP_CLIENTS.has(r.tool)) {
      for (const hdr of r.headers) for (const m of hdr.matchAll(HOST_HDR_RE)) add(m[1], `the Host header "${m[1]}"`);
    }
    for (const f of r.lists) {
      const res = readTargets(f, cwd);
      if (res.problem) deny.push(`${r.tool}: ${res.problem}.`);
      else res.items.forEach(t => add(t, `"${t}" (in ${f})`));
    }
    for (const f of r.requests) {
      const res = readRequestHost(f, cwd);
      if (res.problem) deny.push(`${r.tool}: ${res.problem}.`);
      else add(res.host, `the Host header in ${f}`);
    }
    for (const net of r.cidrs) {
      if (!cidrCovered(net, c)) deny.push(`${r.tool} ${net}: the range isn't entirely inside an in-scope CIDR, or it contains an out-of-scope address. Scan the in-scope hosts only.`);
    }
    const mentioned = new Set();
    for (const t of r.mentions) {
      const h = canonHost(t);
      if (h.problem) {
        if (LOOKALIKE.test(t)) deny.push(`Can't tell which host ${JSON.stringify(t)} goes to: ${h.problem}.`);
        continue;
      }
      if (h.host && !explicit.has(h.host)) mentioned.add(h.host);
    }
    const stateChanging = !READ_METHODS.has(r.method);
    const checks = [...[...explicit.keys()].map(h => [h, true]), ...[...mentioned].map(h => [h, false])];
    for (const [host, isExplicit] of checks) {
      const cls = classify(host, c);
      if (!isExplicit && (cls === 'ALLOWED' || cls === 'UNKNOWN')) continue; // file name, payload string...
      hosts.push({ host, cls, method: r.method });
      if (cls === 'OOS') { deny.push(`${host} is OUT OF SCOPE (notes/scope.json outOfScope). Do not send requests there.`); continue; }
      if (cls === 'OOS_UNLISTED') { deny.push(`${host} is not listed in inScope and its domain is under denyUnlisted (unlisted hosts = out of scope). Do not send requests there.`); continue; }
      if (cls === 'UNKNOWN') { deny.push(`${host} is not in notes/scope.json. Non-target helper (docs/CDN) → ask the human to add it to allowHosts; your OOB → hunterInfra; listed by the program → the human adds it to inScope; otherwise drop it.`); continue; }
      if (cls === 'ALLOWED') continue;
      if (r.tool === 'chrome') { deny.push(`${host} is the target. Claude in Chrome drives your own Chrome (your sessions, no program UA tag) and is only for the platform's report form. Test the target in the Playwright browser.`); continue; }
      if (stale) {
        deny.push(`Scope not confirmed for the current notes/scope.json (it changed, or was never confirmed). Review inScope/outOfScope, then run \`bountyproof scope confirm\` (or tools/scripts/confirm-scope.ps1) before testing ${host}. requireConfirm=true blocks live in-scope testing until confirmed.`);
        continue;
      }
      if (isExplicit && r.follow) { deny.push(r.follow); continue; }
      if (r.tool === 'browser') continue;

      const reqText = [r.ua, ...r.headers].join('\n').toLowerCase();
      const uaTag = String(c.raw.uaTag || '');
      if (uaTag && !reqText.includes(uaTag.toLowerCase())) {
        deny.push(`Request to in-scope ${host} is missing the program UA tag. Add: -A "<browser UA> ${uaTag}" (or -UserAgent in PowerShell).`);
      }
      for (const h of Array.isArray(c.raw.requiredHeaders) ? c.raw.requiredHeaders : []) {
        if (!reqText.includes(String(h).toLowerCase())) deny.push(`Request to in-scope ${host} is missing required header: ${h}`);
      }
      const isGraphqlRead = /graphql/i.test(r.dests.join(' ')) && !/\bmutation\b/i.test(r.body);
      if (c.raw.confirmStateChanging !== false && stateChanging && !isGraphqlRead) {
        ask.push(`State-changing ${r.method} to LIVE in-scope host ${host}. Confirm this is your own test account/object and the action is non-destructive.`);
      }
    }
  }

  const uniq = a => [...new Set(a)];
  const decision = deny.length ? 'deny' : ask.length ? 'ask' : null;
  if (hosts.length || deny.length) log({ tool: tname, decision: decision || 'allow', hosts, reasons: uniq([...deny, ...ask]), cmd: redact(raw) });
  if (!decision) return null;
  return out(decision, `[scope-guard] ${uniq(decision === 'deny' ? deny : ask).join(' | ')}`);
}

// ------------------------------------------------------------------------------------------------
// The scope in the agents' context (SessionStart, SubagentStart)
// ------------------------------------------------------------------------------------------------

export function scopeContext(c) {
  if (!c || c.off || !c.active) return null;
  if (c.errors.length) {
    return `[scope-guard] notes/scope.json is invalid, so every network command is blocked until it's fixed: ${c.errors.slice(0, 6).join('; ')}.`;
  }
  const raw = c.raw;
  const list = (v, n = 80) => {
    const a = Array.isArray(v) ? v.map(x => (typeof x === 'string' ? x : x && x.asset ? String(x.asset) : JSON.stringify(x))) : [];
    if (!a.length) return '(none)';
    return a.slice(0, n).join(', ') + (a.length > n ? `, ... (+${a.length - n} more in notes/scope.json)` : '');
  };
  const lines = [
    '[scope-guard] The scope of this engagement, from notes/scope.json. The scope-guard hook enforces it on every command and navigation, and a block is final.',
    `- OUT OF SCOPE (never send anything there, even when a wildcard below covers it): ${list(raw.outOfScope)}`,
  ];
  if (Array.isArray(raw.denyUnlisted) && raw.denyUnlisted.length) lines.push(`- Any host not listed is out of scope under: ${list(raw.denyUnlisted)}`);
  lines.push(`- IN SCOPE: ${list(raw.inScope)}`);
  lines.push('- How the rules match: an exact host is only that host, not its subdomains; *.example.com is any subdomain of example.com at any depth, but not example.com itself; out of scope wins over everything. A host found by recon is out of scope unless a rule above covers it.');
  const hdrs = Array.isArray(raw.requiredHeaders) ? raw.requiredHeaders.filter(Boolean) : [];
  if (raw.uaTag || hdrs.length) {
    lines.push(`- Every request to an in-scope host carries${raw.uaTag ? ` the UA tag "${raw.uaTag}"` : ''}${raw.uaTag && hdrs.length ? ' and' : ''}${hdrs.length ? ` the headers ${hdrs.join(', ')}` : ''}.`);
  }
  if (Array.isArray(raw.needsReview) && raw.needsReview.length) {
    lines.push(`- Listed by the program but NOT rules until the human decides (needsReview): ${list(raw.needsReview, 30)}`);
  }
  if (raw.requireConfirm === true && scopeHash(raw) !== (raw.confirmedScope || '')) {
    lines.push('- The scope is not confirmed: live in-scope testing is blocked until the human runs `bountyproof scope confirm` in their own terminal.');
  }
  return lines.join('\n');
}

function handle(input) {
  const event = input.hook_event_name || 'PreToolUse';
  const c = loadScope();
  if (!c) return null; // no notes/scope.json: not an engagement workspace
  if (event === 'SessionStart' || event === 'SubagentStart') {
    const ctx = scopeContext(c);
    return ctx ? { hookSpecificOutput: { hookEventName: event, additionalContext: ctx } } : null;
  }
  if (event !== 'PreToolUse') return null;
  const cwd = input.cwd || projectDir;
  const ti = input.tool_input || {};
  const tname = input.tool_name || '';

  if ((tname === 'Bash' || tname === 'PowerShell') && confirmsScope(String(ti.command || ''), tname === 'PowerShell')) {
    log({ tool: tname, decision: 'deny', reasons: ['scope confirmation attempted by the agent'], cmd: redact(ti.command) });
    return out('deny', "[scope-guard] Confirming the scope is the human's step. Ask them to review notes/scope.json against the program page and run `bountyproof scope confirm` in their own terminal.");
  }
  const live = !c.off && c.active;
  const scoped = live ? decide(input, c, cwd) : null;
  if (scoped?.hookSpecificOutput.permissionDecision === 'deny') return scoped;
  if (live && changesProtected(input, cwd)) {
    log({ tool: tname, decision: 'ask', reasons: ['change to the scope or the guard'], cmd: redact(ti.command || ti.file_path || '') });
    return out('ask', "[scope-guard] This changes notes/scope.json, the scope guard or the workspace settings. The scope is the human's: approve only if the change matches the program page. A change to inScope/outOfScope/denyUnlisted also needs `bountyproof scope confirm` again.");
  }
  return submitGate(input) || scoped;
}

function isWorkspaceCopy() {
  try { return fs.realpathSync(SELF) === fs.realpathSync(WORKSPACE_COPY); } catch { return false; }
}

function main() {
  if (fs.existsSync(WORKSPACE_COPY) && !isWorkspaceCopy()) process.exit(0);
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => { buf += chunk; }).on('end', () => {
    let result = null;
    try {
      result = handle(JSON.parse(buf));
    } catch (e) {
      log({ error: String((e && e.stack) || e) });
      result = {
        systemMessage: `[scope-guard] Internal error: this call was NOT checked against the scope (${String((e && e.message) || e).slice(0, 160)}). It went ahead so a guard bug can't stop the session. Check its hosts by hand with \`bountyproof scope check\`, and report the error (it's in notes/egress-log.jsonl).`,
      };
    }
    if (result) process.stdout.write(JSON.stringify(result));
    process.exit(0);
  });
}

const isMain = (() => {
  try { return Boolean(process.argv[1]) && fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(SELF); } catch { return false; }
})();
if (isMain) main();
