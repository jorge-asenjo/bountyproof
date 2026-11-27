"""The workspace scope: how hosts and rules are read, confirmation, and dry-run checks.

The host and rule functions mirror ``hooks/scope-guard.mjs`` (``canonHost``, ``canonRule``,
``compileScope``, ``classify``, ``ruleText``), so a rule written here (``bountyproof scope import``) is
read by the hook as the same rule. ``tests/scope-cases.json`` holds the cases both must agree on.

The confirmation hash must match the hook byte for byte: the three scope lists, each trimmed,
lowercased, de-duplicated and ordinal-sorted, joined, then SHA-256 hex.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from bountyproof.assets import hook_path

SCOPE_LISTS = ("inScope", "outOfScope", "denyUnlisted")
RULE_LISTS = {
    "inScope": "in",
    "outOfScope": "out",
    "denyUnlisted": "out",
    "allowHosts": "allow",
    "hunterInfra": "allow",
}
BOOL_FIELDS = ("enforce", "requireConfirm", "confirmStateChanging")
STRING_FIELDS = ("uaTag", "confirmedScope")
DEFAULT_ALLOW = (
    "localhost", "127.0.0.1", "::1", "github.com", "*.github.com", "*.githubusercontent.com",
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crt.sh", "web.archive.org",
    "*.yeswehack.com", "yeswehack.com", "*.intigriti.com", "intigriti.com", "*.hackerone.com",
    "hackerone.com", "*.bugcrowd.com", "bugcrowd.com", "*.anthropic.com", "claude.ai", "*.claude.ai",
)  # fmt: skip

_ASCII_WS = " \t\n\v\f\r"
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_DOTTED_QUAD = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}$")
_NUMERIC_LABEL = re.compile(r"^(?:[0-9]+|0x[0-9a-f]*)$")
_CIDR = re.compile(r"^((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-f]*:[0-9a-f:.]*)/([0-9]{1,3})$")
_NOT_PRINTABLE_ASCII = re.compile(r"[^\x21-\x7e]")
# Second-level labels that form a public suffix under a two-letter country code (co.uk, com.au...).
_SLD = {"ac", "co", "com", "edu", "gov", "gob", "go", "ltd", "mil", "ne", "net", "nic", "or", "org", "plc", "sch"}


class ScopeError(RuntimeError):
    pass


# ------------------------------------------------------------------------------------------------
# Hosts
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Host:
    """The host a client connects to, or why the guard can't tell (``problem``)."""

    host: str | None = None
    problem: str | None = None
    local: bool = False  # file:// — not a network destination


def canon_host(token: str) -> Host:
    t = str(token).strip(_ASCII_WS)
    m = _SCHEME.match(t)
    if m and m.group(1).lower() == "file":
        return Host(local=True)
    rest = t[m.end() :] if m else t
    end = re.search(r"[/?#]", rest)
    return _from_authority(rest[: end.start()] if end else rest)


def _from_authority(auth: str) -> Host:
    if not auth:
        return Host(problem="there is no host")
    if _NOT_PRINTABLE_ASCII.search(auth):
        return Host(
            problem="the host has a non-ASCII, space or control character (write an IDN host in punycode, xn--...)"
        )
    if "$" in auth:
        return Host(
            problem="the host is a shell variable or a placeholder: write it literally so the guard can check it"
        )
    if re.search(r"[{}]", auth):
        return Host(problem="a curl glob in the host expands to hosts the guard never sees")
    if re.search(r"[\\%|^`<>\"']", auth):
        return Host(problem="the host has a character that HTTP clients read differently (\\ % | ^ and quotes)")
    at = auth.split("@")
    if len(at) > 2:
        return Host(problem="the host part has more than one @")
    hp = at[-1]
    if hp.startswith("["):
        close = hp.find("]")
        v6 = None if close < 0 or not re.fullmatch(r"(?::[0-9]*)?", hp[close + 1 :]) else _parse_ipv6(hp[1:close])
        return Host(host=_format_ipv6(v6)) if v6 else Host(problem="not a valid IPv6 address")
    if re.search(r"[\[\]]", hp):
        return Host(problem="a curl glob in the host expands to hosts the guard never sees")
    colon = hp.find(":")
    if colon >= 0 and not re.fullmatch(r"[0-9]*", hp[colon + 1 :]):
        return Host(problem="not a valid port")
    return _host_name(hp[:colon] if colon >= 0 else hp)


def _host_name(raw: str) -> Host:
    host = raw.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return Host(problem="there is no host")
    labels = host.split(".")
    # WHATWG URL: a host whose last label is a number is an IPv4 address (decimal, octal or hex parts)
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        ip = _parse_ipv4(host)
        return Host(host=ip) if ip else Host(problem="not a valid IPv4 address")
    if len(host) > 253 or not all(_LABEL.fullmatch(label) for label in labels):
        return Host(problem="not a valid host name")
    return Host(host=host)


def _ipv4_part(p: str) -> int | None:
    if p == "":
        return None
    radix = 10
    if p[:2].lower() == "0x":
        p, radix = p[2:], 16
    elif len(p) > 1 and p[0] == "0":
        p, radix = p[1:], 8
    if p == "":
        return 0
    digits = {16: "0123456789abcdefABCDEF", 8: "01234567", 10: "0123456789"}[radix]
    return int(p, radix) if all(ch in digits for ch in p) else None


def _parse_ipv4(s: str) -> str | None:
    parts = s.split(".")
    if len(parts) > 4:
        return None
    nums = [_ipv4_part(p) for p in parts]
    if any(n is None for n in nums):
        return None
    last = nums.pop()
    if any(n > 255 for n in nums) or last >= 256 ** (4 - len(nums)):
        return None
    v = last + sum(n * 256 ** (3 - i) for i, n in enumerate(nums))
    return ".".join(str(b) for b in v.to_bytes(4, "big"))


def _parse_ipv6(s: str) -> list[int] | None:
    """The WHATWG URL IPv6 parser: eight 16-bit pieces, or None."""
    a = [0] * 8
    piece, compress, i, n = 0, None, 0, len(s)

    def at(k: int) -> str:
        return s[k] if k < n else ""

    if at(0) == ":":
        if at(1) != ":":
            return None
        i, piece, compress = 2, 1, 1
    while i < n:
        if piece == 8:
            return None
        if s[i] == ":":
            if compress is not None:
                return None
            i += 1
            piece += 1
            compress = piece
            continue
        value = length = 0
        while length < 4 and at(i) and at(i) in "0123456789abcdefABCDEF":
            value = value * 16 + int(s[i], 16)
            i += 1
            length += 1
        if at(i) == ".":
            if length == 0:
                return None
            i -= length
            if piece > 6:
                return None
            seen = 0
            while i < n:
                v4 = None
                if seen > 0:
                    if s[i] == "." and seen < 4:
                        i += 1
                    else:
                        return None
                if not (at(i) and at(i) in "0123456789"):
                    return None
                while at(i) and at(i) in "0123456789":
                    d = int(s[i])
                    if v4 is None:
                        v4 = d
                    elif v4 == 0:
                        return None
                    else:
                        v4 = v4 * 10 + d
                    if v4 > 255:
                        return None
                    i += 1
                a[piece] = a[piece] * 256 + v4
                seen += 1
                if seen in (2, 4):
                    piece += 1
            if seen != 4:
                return None
            break
        elif at(i) == ":":
            i += 1
            if i >= n:
                return None
        elif i < n:
            return None
        a[piece] = value
        piece += 1
    if compress is not None:
        swaps, piece = piece - compress, 7
        while piece != 0 and swaps > 0:
            a[piece], a[compress + swaps - 1] = a[compress + swaps - 1], a[piece]
            piece -= 1
            swaps -= 1
    elif piece != 8:
        return None
    return a


def _format_ipv6(a: list[int]) -> str:
    """RFC 5952 text. An IPv4-mapped address (::ffff:a.b.c.d) is the IPv4 address it connects to."""
    if all(x == 0 for x in a[:5]) and a[5] == 0xFFFF:
        return f"{a[6] >> 8}.{a[6] & 255}.{a[7] >> 8}.{a[7] & 255}"
    best, best_len, i = -1, 0, 0
    while i < 8:
        if a[i] != 0:
            i += 1
            continue
        j = i
        while j < 8 and a[j] == 0:
            j += 1
        if j - i > best_len:
            best, best_len = i, j - i
        i = j
    hexes = [format(x, "x") for x in a]
    if best_len < 2:
        return ":".join(hexes)
    return ":".join(hexes[:best]) + "::" + ":".join(hexes[best + best_len :])


def _v6_to_int(a: list[int]) -> int:
    v = 0
    for x in a:
        v = (v << 16) | x
    return v


def _v4_to_int(h: str) -> int:
    v = 0
    for x in h.split("."):
        v = v * 256 + int(x)
    return v


def is_ipv4(h: str) -> bool:
    return bool(_DOTTED_QUAD.fullmatch(h))


def _is_ip(h: str) -> bool:
    return is_ipv4(h) or ":" in h


# ------------------------------------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    kind: str  # host | ip | wild | glob | cidr4 | cidr6
    value: str = ""  # the host or IP, the wildcard's base domain, or the glob pattern
    net: int = 0
    mask: int = 0
    bits: int = 0

    @property
    def text(self) -> str:
        """The rule as scope.json text, in the one form ``canon_rule`` reads back as the same rule."""
        if self.kind == "wild":
            return f"*.{self.value}"
        if self.kind == "cidr4":
            return f"{'.'.join(str(b) for b in self.net.to_bytes(4, 'big'))}/{self.bits}"
        if self.kind == "cidr6":
            pieces = [(self.net >> (16 * i)) & 0xFFFF for i in range(7, -1, -1)]
            return f"{_format_ipv6(pieces)}/{self.bits}"
        return self.value


@dataclass(frozen=True)
class Canon:
    rule: Rule | None = None
    problem: str | None = None


def is_public_suffix(host: str) -> bool:
    labels = host.split(".")
    return len(labels) == 1 or (len(labels) == 2 and labels[0] in _SLD and len(labels[1]) == 2)


def punycode(host: str) -> str | None:
    """``host`` in punycode (stdlib IDNA 2003), or None if it can't be encoded."""
    wild = host.startswith("*.")
    try:
        ascii_host = (host[2:] if wild else host).encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return ("*." if wild else "") + ascii_host if ascii_host.isascii() else None


def _unicode_problem(rule: str) -> str:
    host = re.split(r"[/?#:]", re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", rule))[0]
    ascii_host = punycode(host)
    if ascii_host and not _NOT_PRINTABLE_ASCII.search(ascii_host):
        return f"not ASCII: write it in punycode, as {ascii_host}"
    return "not ASCII: write the host in punycode (xn--...)"


def _cidr4(n: int, bits: int) -> Canon:
    mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return Canon(Rule("cidr4", net=n & mask, mask=mask, bits=bits))


def _cidr_rule(ip_text: str, bits: int) -> Canon:
    if ":" in ip_text:
        v6 = _parse_ipv6(ip_text)
        if not v6 or bits > 128:
            return Canon(problem="not a valid IPv6 CIDR")
        if bits >= 96 and all(x == 0 for x in v6[:5]) and v6[5] == 0xFFFF:
            return _cidr4(v6[6] * 65536 + v6[7], bits - 96)
        full = (1 << 128) - 1
        mask = 0 if bits == 0 else full ^ ((1 << (128 - bits)) - 1)
        return Canon(Rule("cidr6", net=_v6_to_int(v6) & mask, mask=mask, bits=bits))
    if not _DOTTED_QUAD.fullmatch(ip_text) or bits > 32:
        return Canon(problem="not a valid IPv4 CIDR (write a.b.c.d/n)")
    return _cidr4(_v4_to_int(ip_text), bits)


def _wild_rule(s: str, side: str) -> Canon:
    if s.startswith("*.") and "*" not in s[2:]:
        base = _host_name(s[2:])
        if base.problem or _is_ip(base.host or ""):
            return Canon(problem="a wildcard needs a domain after *.")
        if side != "out" and is_public_suffix(base.host):
            return Canon(problem=f"*.{base.host} would cover a whole TLD or public suffix")
        return Canon(Rule("wild", base.host))
    if side != "out":
        return Canon(
            problem="a * anywhere but the start (*.domain) can only exclude: put it in outOfScope or denyUnlisted"
        )
    if not re.fullmatch(r"[a-z0-9.*_-]+", s) or not re.search(r"[a-z0-9]", s.replace("*", "")):
        return Canon(problem="a pattern that would match every host")
    return Canon(Rule("glob", s))


def canon_rule(rule: object, side: str = "in") -> Canon:
    """One scope.json entry → the rule the guard enforces, or why it can't be enforced exactly."""
    if not isinstance(rule, str):
        return Canon(problem="not a string")
    r = re.sub(r"[,;]+$", "", rule.strip(_ASCII_WS))
    r = re.sub(r"[,;]+$", "", re.sub(r"^[`\"']+|[`\"']+$", "", r)).strip(_ASCII_WS)
    if not r:
        return Canon(problem="empty")
    if re.search(r"\s", r):
        return Canon(problem="free text, not a host, wildcard, IP or CIDR")
    if _NOT_PRINTABLE_ASCII.search(r):
        return Canon(problem=_unicode_problem(r))
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", r.lower())
    cidr = _CIDR.fullmatch(s)
    if cidr:
        return _cidr_rule(cidr.group(1), int(cidr.group(2)))
    cut = re.search(r"[/?#]", s)
    if cut:
        s = s[: cut.start()]  # scope is per host: a path can't be enforced, the host is
    at = s.split("@")
    if len(at) > 2:
        return Canon(problem="more than one @")
    s = at[-1]
    if s.startswith("[") or s.count(":") > 1:
        inner: str | None = s
        if s.startswith("["):
            close = s.find("]")
            inner = None if close < 0 or not re.fullmatch(r"(?::[0-9]*)?", s[close + 1 :]) else s[1:close]
        v6 = _parse_ipv6(inner) if inner is not None else None
        return Canon(Rule("ip", _format_ipv6(v6))) if v6 else Canon(problem="not a valid IPv6 address")
    colon = s.find(":")
    if colon >= 0:
        if not re.fullmatch(r"[0-9]*", s[colon + 1 :]):
            return Canon(problem="not a valid port")
        s = s[:colon]
    if s.endswith("."):
        s = s[:-1]
    if "*" in s:
        return _wild_rule(s, side)
    if re.search(r"[^a-z0-9._-]", s):
        return Canon(problem="not a host, wildcard, IP or CIDR")
    if _NUMERIC_LABEL.fullmatch(s.split(".")[-1]):
        if _DOTTED_QUAD.fullmatch(s):
            return Canon(Rule("ip", s))
        return Canon(problem="write an IPv4 address as plain dotted decimal (a.b.c.d)")
    h = _host_name(s)
    return Canon(problem=h.problem) if h.problem else Canon(Rule("host", h.host))


def _glob_re(pattern: str) -> re.Pattern[str]:
    return re.compile("^" + pattern.replace(".", r"\.").replace("*", "[a-z0-9._-]*") + "$")


def rule_matches(rule: Rule, host: str) -> bool:
    if rule.kind in ("host", "ip"):
        return host == rule.value
    if rule.kind == "wild":
        return host.endswith("." + rule.value)
    if rule.kind == "glob":
        return bool(_glob_re(rule.value).match(host))
    if rule.kind == "cidr4":
        return is_ipv4(host) and (_v4_to_int(host) & rule.mask) == rule.net
    if rule.kind == "cidr6":
        v6 = _parse_ipv6(host) if ":" in host else None
        return v6 is not None and (_v6_to_int(v6) & rule.mask) == rule.net
    return False


def _match_any(host: str, rules: list[Rule]) -> bool:
    return any(rule_matches(r, host) for r in rules)


def _is_local_ip(host: str) -> bool:
    if host == "::1":
        return True
    if not is_ipv4(host):
        return False
    n = _v4_to_int(host)
    return n >> 24 in (10, 127) or n >> 16 == 0xC0A8 or n >> 20 == 0xAC1


_DEFAULT_ALLOW_RULES = [c.rule for c in (canon_rule(r, "allow") for r in DEFAULT_ALLOW) if c.rule]


@dataclass
class Compiled:
    """A scope.json as the guard enforces it."""

    raw: dict = field(default_factory=dict)
    in_scope: list[Rule] = field(default_factory=list)
    out_of_scope: list[Rule] = field(default_factory=list)
    deny_unlisted: list[Rule] = field(default_factory=list)
    allow: list[Rule] = field(default_factory=lambda: list(_DEFAULT_ALLOW_RULES))
    errors: list[str] = field(default_factory=list)
    active: bool = True
    off: bool = False


def _json(v: object) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def compile_scope(raw: object) -> Compiled:
    """Parsed scope.json → the rules and every reason the file can't be enforced as written."""
    c = Compiled()
    if not isinstance(raw, dict):
        c.errors.append("notes/scope.json must be a JSON object")
        return c
    c.raw = raw
    for k in BOOL_FIELDS:
        if raw.get(k) is not None and not isinstance(raw[k], bool):
            c.errors.append(f"{k} must be true or false, not {_json(raw[k])}")
    for k in STRING_FIELDS:
        if raw.get(k) is not None and not isinstance(raw[k], str):
            c.errors.append(f"{k} must be a string")
    hdrs = raw.get("requiredHeaders")
    if hdrs is not None and not (isinstance(hdrs, list) and all(isinstance(h, str) for h in hdrs)):
        c.errors.append("requiredHeaders must be a list of strings")
    targets = {"inScope": c.in_scope, "outOfScope": c.out_of_scope, "denyUnlisted": c.deny_unlisted}
    for key, side in RULE_LISTS.items():
        items = raw.get(key)
        if items is None:
            continue
        if not isinstance(items, list):
            c.errors.append(f"{key} must be a list")
            continue
        for item in items:
            res = canon_rule(item, side)
            if res.problem:
                c.errors.append(f"{key} entry {_json(item)}: {res.problem}")
            else:
                (c.allow if side == "allow" else targets[key]).append(res.rule)
    c.off = raw.get("enforce") is False
    ins = raw.get("inScope")
    c.active = not c.off and ins is not None and not (isinstance(ins, list) and not ins)
    return c


def classify(host: str, c: Compiled) -> str:
    """OOS | IN_SCOPE | OOS_UNLISTED | ALLOWED | UNKNOWN for a canonical host."""
    if _match_any(host, c.out_of_scope):
        return "OOS"
    if _match_any(host, c.in_scope):
        return "IN_SCOPE"
    if _match_any(host, c.deny_unlisted):
        return "OOS_UNLISTED"
    if _match_any(host, c.allow) or _is_local_ip(host):
        return "ALLOWED"
    return "UNKNOWN"


# ------------------------------------------------------------------------------------------------
# The workspace file
# ------------------------------------------------------------------------------------------------


def load(scope_file: Path) -> dict:
    try:
        # utf-8-sig: Windows PowerShell 5.1 saves with a BOM, and the hook reads it either way
        return json.loads(scope_file.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise ScopeError(f"{scope_file} not found. Run this from an engagement workspace.") from None
    except json.JSONDecodeError as exc:
        raise ScopeError(f"{scope_file} is not valid JSON: {exc}") from None


def save(scope_file: Path, scope: dict) -> None:
    scope_file.write_text(json.dumps(scope, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _canon(values: object) -> str:
    items = values if isinstance(values, list) else []
    unique = {str(v).strip().lower() for v in items if str(v).strip()}
    return ",".join(sorted(unique))


def scope_hash(scope: dict) -> str:
    canon = "|".join(f"{key}={_canon(scope.get(key))}" for key in SCOPE_LISTS)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def is_confirmed(scope: dict) -> bool:
    return scope.get("confirmedScope") == scope_hash(scope)


def confirm(scope_file: Path, scope: dict) -> str:
    digest = scope_hash(scope)
    scope["confirmedScope"] = digest
    save(scope_file, scope)
    return digest


@dataclass(frozen=True)
class Verdict:
    decision: str  # allow | ask | deny | inactive
    reason: str = ""


def check(workspace: Path, target: str, ua: str | None = None) -> Verdict:
    """Ask the hook what it would do with a request, without sending anything.

    ``target`` is a URL (checked as a curl GET carrying the program's UA tag) or a full shell command.
    """
    data = load(workspace / "notes" / "scope.json")
    compiled = compile_scope(data)
    if not compiled.errors and (compiled.off or not compiled.active):
        return Verdict("inactive", "notes/scope.json has no inScope entries yet, so the guard is off.")

    if " " in target.strip():
        command = target
    else:
        tag = ua if ua is not None else str(data.get("uaTag") or "") if isinstance(data, dict) else ""
        command = f"curl -A {shlex.quote(('Mozilla/5.0 ' + tag).strip())} {shlex.quote(target)}"

    node = shutil.which("node")
    if node is None:
        raise ScopeError("Node.js is required to run the scope guard (https://nodejs.org).")

    local = workspace / ".claude" / "hooks" / "scope-guard.mjs"
    hook = local if local.is_file() else hook_path()
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(workspace), "BOUNTYPROOF_DRY_RUN": "1"}
    proc = subprocess.run([node, str(hook)], input=payload, capture_output=True, encoding="utf-8", env=env, timeout=30)
    if not proc.stdout.strip():
        return Verdict("allow")
    result = json.loads(proc.stdout)
    out = result.get("hookSpecificOutput", {})
    if not out and result.get("systemMessage"):
        return Verdict("allow", result["systemMessage"])
    return Verdict(out.get("permissionDecision", "allow"), out.get("permissionDecisionReason", ""))
