"""``bountyproof scope import``: fill notes/scope.json from a program's published scope.

Sources (standard library only, no API key for public programs):

* bounty-targets-data, the public, hourly dumps of HackerOne, Bugcrowd, Intigriti and YesWeHack
  program scopes (https://github.com/arkadiyt/bounty-targets-data);
* the text of a program page, pasted into a file: its "In scope" / "Out of scope" lists, plus the
  researcher-conduct rules found in it.

The hook enforces every rule per host and trusts it, so the importer fails closed:

* only an entry that is unambiguously a host, a wildcard, an IP or a CIDR becomes a rule, and every
  rule goes through ``scope.canon_rule``, so the hook reads it exactly as written. An exact host in
  scope.json is only that host, never its subdomains;
* anything else (paths, free text, placeholders like ``<your-tenant>``, a mid-label wildcard on the
  in-scope side, public suffixes, IDN hosts that clients encode differently) goes to ``needsReview``
  and is NOT a rule until a person moves it;
* an out-of-scope host is denied even when the program wrote prose after it;
* non-web assets (mobile apps, source code, hardware) go to ``otherAssets``, for reference;
* in a white-box workspace every program asset goes to ``outOfScope``: the work happens in the lab.

``_import`` records what the last import wrote, so a re-import refreshes those rules and keeps the
ones written by hand. Any change to the scope lists changes the confirmation hash: the human has to
review the scope and run ``bountyproof scope confirm`` again.

Ported from ``cbh/scope_import.py`` in Claude-BugHunter
(https://github.com/elementalsouls/Claude-BugHunter, commit 9796bee), which carries this notice:

    MIT License

    Copyright (c) 2026 Sachin Sharma

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

Changed from theirs: it writes scope.json instead of scope.md (no regex rules, no markers), checks
every rule against the guard's own parser, denies an out-of-scope host followed by prose, sends IDN
hosts with deviation characters to review, handles ``Type | Asset`` tables and emphasis in pasted
text (their fix for issue #235), and knows white-box workspaces.
"""

from __future__ import annotations

import datetime as dt
import difflib
import ipaddress
import json
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from bountyproof import profile, scope

SOURCE_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{platform}_data.json"
SOURCE_HOME = "https://github.com/arkadiyt/bounty-targets-data"
CACHE_MAX_AGE = 6 * 3600  # the upstream dump refreshes hourly
MAX_DOWNLOAD = 128 * 1024 * 1024
FETCH_TIMEOUT = 60
USER_AGENT = "bountyproof-scope-import"

PLATFORMS = {
    "h1": "hackerone",
    "hackerone": "hackerone",
    "bugcrowd": "bugcrowd",
    "bc": "bugcrowd",
    "intigriti": "intigriti",
    "int": "intigriti",
    "yeswehack": "yeswehack",
    "ywh": "yeswehack",
}
PLATFORM_NAMES = {"hackerone": "HackerOne", "bugcrowd": "Bugcrowd", "intigriti": "Intigriti", "yeswehack": "YesWeHack"}
PLATFORM_HOSTS = {
    "hackerone.com": "hackerone",
    "bugcrowd.com": "bugcrowd",
    "intigriti.com": "intigriti",
    "app.intigriti.com": "intigriti",
    "yeswehack.com": "yeswehack",
}

# Asset types whose identifier names a host, an IP or a network. Everything else (mobile apps, source
# code, hardware, executables, "other") is not a host rule on the in-scope side.
HOST_TYPES = {
    "url",
    "wildcard",
    "ip_address",
    "cidr",
    "api",  # HackerOne
    "website",
    "network",  # Bugcrowd
    "iprange",  # Intigriti
    "web-application",  # YesWeHack
}
# Never a host, even on the out-of-scope side, where an untyped or "other" identifier that parses as a
# host still becomes a deny rule.
NON_HOST_TYPES = {
    "google_play_app_id",
    "apple_store_app_id",
    "windows_app_store_app_id",
    "testflight",
    "other_apk",
    "other_ipa",
    "source_code",
    "downloadable_executables",
    "hardware",
    "smart_contract",
    "ai_model",
    "ios",
    "android",
    "iot",
    "device",
    "application",
    "mobile-application",
    "mobile-application-android",
    "mobile-application-ios",
}

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
# Characters that IDNA 2003 and 2008 (curl, browsers) encode differently.
_IDN_DEVIATIONS = set("ßς")
_IP_RANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_BRACES = re.compile(r"\{([^{}]*)\}")
_HOSTISH = re.compile(r"^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)+(?::\d+)?$|^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$", re.I)


class ScopeImportError(RuntimeError):
    pass


# ================================================================================================
# Data model
# ================================================================================================
@dataclass
class Entry:
    side: str  # "in" | "out"
    raw: str  # the identifier as the program wrote it
    asset_type: str = ""
    status: str = "review"  # "rule" | "review" | "other" | "covered"
    rules: list = field(default_factory=list)  # rule texts as scope.json gets them
    reason: str = ""  # why it isn't a rule (review), or a note on the rule
    bounty: object = None  # True / False / None (unknown)
    severity: str = ""
    instruction: str = ""
    suggest: str = ""  # a path-limited in-scope entry: the rule for the whole host


@dataclass
class Program:
    platform: str
    handle: str
    name: str = ""
    url: str = ""
    source: str = ""
    entries: list = field(default_factory=list)
    conduct: list = field(default_factory=list)  # researcher-conduct rules found in the text
    exclusions: list = field(default_factory=list)  # out-of-scope finding classes (pasted text)

    def rules(self, side: str) -> list[str]:
        out: list[str] = []
        for e in self.entries:
            if e.side == side and e.status == "rule":
                out.extend(r for r in e.rules if r not in out)
        return out

    def review(self) -> list[dict]:
        items = []
        for e in self.entries:
            if e.status != "review":
                continue
            item = {"side": e.side, "asset": e.raw, "why": e.reason}
            if e.suggest:
                item["suggest"] = e.suggest
            items.append(item)
        return items

    def other(self) -> list[dict]:
        return [
            {"side": e.side, "asset": e.raw, "type": e.asset_type.lower()} for e in self.entries if e.status == "other"
        ]


# ================================================================================================
# Identifier -> rule
# ================================================================================================
def _clean(text: object) -> str:
    s = str(text or "").translate(_ZERO_WIDTH).replace("\xa0", " ").replace("\t", " ")
    return re.sub(r" {2,}", " ", s).strip().rstrip(",;")


def _one_line(text: object, limit: int = 140) -> str:
    s = re.sub(r"\s+", " ", _clean(text)).strip()
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "..."


def _strip_emphasis(s: str) -> str:
    """``**vpn.example.com**`` / ``__x__`` -> the text inside. A ``*.`` wildcard is left alone."""
    m = re.fullmatch(r"(\*\*|__)(.+?)\1", s.strip())
    return m.group(2).strip() if m else s


def _canon(rule: str, side: str) -> tuple[str | None, str]:
    """A candidate rule through the guard's own parser: (rule text, "") or (None, why not)."""
    c = scope.canon_rule(rule, "out" if side == "out" else "in")
    return (c.rule.text, "") if c.rule else (None, c.problem or "not a rule")


def _canon_all(rules: list[str], side: str) -> tuple[list[str] | None, str]:
    out = []
    for r in rules:
        text, why = _canon(r, side)
        if text is None:
            return None, why
        out.append(text)
    return out, ""


def _ip_rules(token: str) -> list[str] | None:
    """An IP, a CIDR or an IPv4 range -> rule texts, else None."""
    t = token.strip("[]")
    try:
        if "/" in t:
            return [str(ipaddress.ip_network(t, strict=False))]
        return [str(ipaddress.ip_address(t.split("%")[0]))]
    except ValueError:
        pass
    m = _IP_RANGE.match(token)
    if not m:
        return None
    first, last = m.group(1), m.group(2)
    if "." not in last:  # 10.0.0.5-87 -> 10.0.0.5 - 10.0.0.87
        last = first.rsplit(".", 1)[0] + "." + last
    try:
        a, b = ipaddress.IPv4Address(first), ipaddress.IPv4Address(last)
    except ValueError:
        return None
    if b < a:
        return None
    return [str(n) for n in ipaddress.summarize_address_range(a, b)]


def _parse_token(token: str, side: str) -> tuple[list[str] | None, str]:
    """One identifier with no spaces -> (rules, note) or (None, why not).

    ``([], "path:/x|rule")`` means a path-limited asset whose host would be ``rule``.
    """
    t = _SCHEME.sub("", token.strip())
    t = t.split("@")[-1] if "@" in t.split("/")[0] else t  # drop userinfo
    ips = _ip_rules(t)
    if ips:
        return _canon_all(ips, side)
    hostport, _, path = t.partition("/")
    path = path.split("#")[0].strip()
    hostport = hostport.split("?")[0].split("#")[0]
    note = ""
    if hostport.startswith("["):  # [v6]:port
        ips = _ip_rules(hostport[1:].split("]")[0])
        return _canon_all(ips, side) if ips else (None, "unparseable IPv6 literal")
    host, _, port = hostport.partition(":")
    if port:
        if not port.isdigit():
            return None, "unparseable host:port"
        note = f"port {port} dropped (the guard checks hosts)"
    host = host.lower().rstrip(".")
    if not host.isascii():
        if _IDN_DEVIATIONS & set(host):
            return (
                None,
                "an IDN with ß or ς, which curl and browsers encode differently: write the punycode the program means",
            )
        ascii_host = scope.punycode(host)
        if not ascii_host:
            return None, "an IDN that can't be written in punycode"
        host, note = ascii_host, ((note + "; ") if note else "") + "IDN written in punycode"
    ips = _ip_rules(host)  # 203.0.113.7:8443/x
    if ips:
        texts, why = _canon_all(ips, side)
        if texts is None:
            return None, why
        return ([], f"path:/{path}|{texts[0]}") if path not in ("", "*", "*/") else (texts, note)
    path_limited = path not in ("", "*", "*/")
    if host.startswith("*.") and "*" not in host[2:]:
        rules = [host]
    elif "*" in host:
        if side != "out":
            return None, "a wildcard in the middle of the host: the guard only takes *.domain on the in-scope side"
        rules = [host]
        note = ((note + "; ") if note else "") + "mid-label wildcard, denied as a pattern"
    elif "." not in host or scope.is_public_suffix(host):
        return None, "not a host with a domain (a public suffix or a shorthand?)"
    else:
        rules = [host]
    text, why = _canon(rules[0], side)
    if text is None:
        return None, why
    if path_limited:
        return [], f"path:/{path}|{text}"
    return [text], note


def _expand_braces(token: str) -> list[str]:
    """``*.brand.{com,jp}`` -> [``*.brand.com``, ``*.brand.jp``] (one group only)."""
    m = _BRACES.search(token)
    if not m:
        return [token]
    return [token[: m.start()] + alt.strip() + token[m.end() :] for alt in m.group(1).split(",")]


def classify(raw: object, asset_type: object, side: str, host_typed: bool | None = None) -> Entry:
    """One program asset -> an Entry (rule / review / other). ``host_typed`` overrides the type lookup."""
    e = Entry(side=side, raw=_one_line(raw, 200), asset_type=str(asset_type or ""))
    s = _strip_emphasis(_clean(raw))
    typ = e.asset_type.lower()
    hosty = typ in HOST_TYPES if host_typed is None else host_typed
    if not s:
        e.reason = "empty identifier"
        return e
    if typ in NON_HOST_TYPES or (not hosty and side == "in"):
        e.status = "other"
        return e
    notes = []
    m = re.match(r"^(\S+)\s+\(([^()]*)\)$", s)  # "host (legacy domain)"
    if m:
        s = m.group(1)
        notes.append(_one_line(m.group(2), 80))
    if s.strip("█ ") == "":
        e.reason = "redacted in the public data; check the program page"
        return e
    if re.fullmatch(r"[^\s,]+(?:\s*,\s*[^\s,]+)+", s):  # "a.com, b.com, 192.0.2.1"
        s = re.sub(r"\s*,\s*", ",", s)
    if _IP_RANGE.match(s):
        tokens = [s]
    elif re.search(r"\s", s):
        first, rest = s.split(None, 1)
        if side == "out" and _HOSTISH.match(_SCHEME.sub("", first).split("/")[0]):
            # an excluded host followed by prose ("billing.example.com - legacy billing") is still excluded
            s, tokens = first, [first]
            notes.append(f"text after the host ignored: {_one_line(rest, 80)}")
        else:
            e.status = "review" if hosty else "other"
            e.reason = "free text, not a single asset"
            return e
    elif re.search(r"[<>\[\]]", s):
        e.status, e.reason = ("review" if hosty else "other"), "a placeholder or a template"
        return e
    else:
        variants = _expand_braces(s) if s.count("{") <= 1 else [s]
        tokens = [x.strip() for v in variants for x in v.split(",")]
    rules, paths = [], []
    for tok in tokens:
        if not tok:
            e.reason = "a list with an empty item (suffix shorthand?)"
            return e
        got, why = _parse_token(tok, side)
        if got is None:
            if not hosty:
                e.status = "other"
                return e
            e.reason = why
            return e
        if why.startswith("path:"):
            p, _, suggestion = why[5:].partition("|")
            paths.append((p, suggestion))
            continue
        rules.extend(got)
        if why:
            notes.append(why)
    if paths and not rules:
        shown = ", ".join(p for p, _ in paths)
        if side == "in":
            e.suggest = paths[0][1]
            e.reason = (
                f"only {shown} is in scope, and the guard checks hosts: "
                f"add {e.suggest} to inScope to test the whole host"
            )
        else:
            e.reason = f"do not test {shown}: a path-level exclusion the guard can't enforce"
        return e
    if paths:
        notes.append("path-limited parts: " + ", ".join(p for p, _ in paths))
    e.status, e.rules = "rule", list(dict.fromkeys(rules))
    e.reason = "; ".join(dict.fromkeys(n for n in notes if n))
    return e


# ================================================================================================
# Platform records -> Program
# ================================================================================================
def _h1_entry(t: dict, side: str) -> Entry:
    e = classify(t.get("asset_identifier"), t.get("asset_type"), side)
    e.bounty = t.get("eligible_for_bounty")
    e.severity = t.get("max_severity") or ""
    e.instruction = _one_line(t.get("instruction") or "", 120)
    return e


def program_from_record(platform: str, rec: dict) -> Program:
    """One bounty-targets-data program record -> Program."""
    platform = PLATFORMS.get(platform, platform)
    targets = rec.get("targets") or {}
    p = Program(
        platform=platform,
        handle=_record_handle(platform, rec),
        name=_one_line(rec.get("name") or "", 120),
        url=rec.get("url") or "",
    )
    for key, side in (("in_scope", "in"), ("out_of_scope", "out")):
        for t in targets.get(key) or []:
            if platform == "hackerone":
                # HackerOne marks out-of-scope assets with eligible_for_submission=false
                p.entries.append(_h1_entry(t, "out" if t.get("eligible_for_submission") is False else side))
            elif platform == "bugcrowd":
                e = classify(t.get("target") or t.get("uri"), t.get("type"), side)
                name = _one_line(t.get("name") or "", 80)
                if name and name.lower() != e.raw.lower():
                    e.instruction = name
                p.entries.append(e)
            elif platform == "intigriti":
                e = classify(t.get("endpoint"), t.get("type"), side)
                impact = str(t.get("impact") or "")
                if impact.lower().startswith("tier"):
                    e.severity = impact
                e.bounty = (
                    False if impact.lower() == "no bounty" else (True if impact.lower().startswith("tier") else None)
                )
                p.entries.append(e)
            else:
                p.entries.append(classify(t.get("target"), t.get("type"), side))
    _mark_covered(p)
    return p


def _mark_covered(p: Program) -> None:
    """A path-limited in-scope asset whose whole host is already in scope needs no review."""
    in_rules = p.rules("in")
    for e in p.entries:
        if e.side == "in" and e.status == "review" and e.suggest and any(_rule_covers(r, e.suggest) for r in in_rules):
            e.status = "covered"


def _rule_covers(rule: str, other: str) -> bool:
    """True when every host ``other`` admits, ``rule`` admits too."""
    if rule == other:
        return True
    try:
        return ipaddress.ip_network(other, strict=False).subnet_of(ipaddress.ip_network(rule, strict=False))
    except (ValueError, TypeError):
        pass
    if rule.startswith("*."):
        base = rule[2:]
        target = other[2:] if other.startswith("*.") else other
        return target.endswith("." + base) or (other.startswith("*.") and target == base)
    return False


# ================================================================================================
# Pasted program text
# ================================================================================================
_LABEL_CLEAN = re.compile(r"^[#>*_`\s-]+|[\s:*_`]+$")
_IN_LABELS = (
    "in scope",
    "in-scope",
    "in scope targets",
    "in-scope targets",
    "targets",
    "assets in scope",
    "in scope assets",
    "scope",
)
_OUT_LABELS = (
    "out of scope",
    "out-of-scope",
    "out of scope targets",
    "oos",
    "not in scope",
    "out-of-scope targets",
    "out of scope assets",
    "exclusions",
    "excluded",
)
# Program-page sections that end an asset list when pasted as plain lines.
_OTHER_LABELS = (
    "rewards",
    "bounties",
    "bounty",
    "bounty table",
    "rules",
    "program rules",
    "policy",
    "program policy",
    "disclosure",
    "disclosure policy",
    "safe harbor",
    "eligibility",
    "faq",
    "contact",
    "response targets",
    "response efficiency",
    "testing guidelines",
    "guidelines",
    "reporting",
    "submission guidelines",
    "known issues",
    "updates",
    "overview",
    "description",
    "severity",
)
# Table header words and asset-type words: never the asset itself, whichever column they sit in.
_NOT_ASSET = {
    "asset",
    "assets",
    "target",
    "targets",
    "domain",
    "domains",
    "identifier",
    "type",
    "asset type",
    "name",
    "url",
    "urls",
    "wildcard",
    "api",
    "cidr",
    "ip",
    "ip address",
    "ip range",
    "iprange",
    "website",
    "web",
    "web application",
    "web-application",
    "network",
    "other",
    "android",
    "ios",
    "mobile",
    "executable",
    "source code",
    "hardware",
    "max severity",
    "severity",
    "bounty",
    "eligible",
    "eligibility",
    "tier",
    "critical",
    "high",
    "medium",
    "low",
    "none",
    "in scope",
    "out of scope",
    "description",
    "notes",
}


def _text_label(line: str) -> str | None:
    label = _LABEL_CLEAN.sub("", line.strip()).lower()
    label = re.sub(r"\s*\(\d+\)$", "", label)  # "In scope (12)"
    if not label or len(label.split()) > 6:
        return None
    if label in _OTHER_LABELS:
        return "other"
    for phrase in _OUT_LABELS:
        if label == phrase or label.startswith(phrase + " ") or label.endswith(" " + phrase):
            return "out"
    for phrase in _IN_LABELS:
        if label == phrase or label.startswith(phrase + " ") or label.endswith(" " + phrase):
            return "in"
    return None


def _cells(line: str) -> list[str]:
    s = re.sub(r"^(?:[-*•+]|\d+[.)])\s+", "", line.strip())  # bullet / numbered list
    if s.startswith("|"):
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            return []  # table separator row
        return [c.strip("`").strip() for c in cells if c.strip()]
    if "\t" in s:
        return [c.strip("`").strip() for c in s.split("\t") if c.strip()]
    return [s.strip().strip("`")] if s.strip() else []


def _asset_cell(line: str) -> str:
    """The cell that names the asset, in either column order (``Asset | Type`` or ``Type | Asset``)."""
    cells = [_strip_emphasis(c) for c in _cells(line)]
    cells = [c for c in cells if c.lower() not in _NOT_ASSET]
    for c in cells:
        if "." in c or ":" in c or "*" in c or _IP_RANGE.match(c):
            return c
    return cells[0] if cells else ""


def program_from_text(text: str, name: str = "program") -> Program:
    """Pasted program-page text -> Program. Lines under an In scope / Out of scope label become assets;
    out-of-scope prose (excluded bug classes) is kept as exclusions; conduct rules come from the whole text."""
    p = Program(platform="text", handle=name, name=name)
    section = None
    for line in text.splitlines():
        if not line.strip():
            continue
        label = _text_label(line)
        if label:
            section = label if label in ("in", "out") else None
            continue
        if line.lstrip().startswith("#"):
            section = None
            continue
        if not section:
            continue
        cell = _asset_cell(line)
        if not cell:
            continue
        first = cell.split(None, 1)[0]
        looks_like_asset = not re.search(r"\s", cell.split(" (")[0]) and "." in cell
        if looks_like_asset or _IP_RANGE.match(cell) or _HOSTISH.match(_SCHEME.sub("", first).split("/")[0]):
            p.entries.append(classify(cell, "", section, host_typed=True))
        elif section == "out":
            p.exclusions.append(_one_line(cell, 160))
        else:
            p.entries.append(classify(cell, "", section, host_typed=True))
    p.conduct = extract_conduct(text)
    _mark_covered(p)
    return p


_CONDUCT = [
    (
        re.compile(
            r"\b\d+\s*(?:requests?|reqs?|rps|r/s)\b[^.\n]{0,40}?\b(?:per|/|a|every)\s*(?:second|sec|s|minute|min|hour)\b",
            re.I,
        ),
        "rate limit",
    ),
    (re.compile(r"\b(?:automated|automatic)\s+(?:scan\w*|tool\w*|testing)\b", re.I), "automation"),
    (
        re.compile(
            r"\b(?:user-agent|x-[a-z0-9-]{2,}|header)\b[^.\n]{0,60}\b(?:must|required|include|add|set)\b|"
            r"\b(?:must|required|include|add|set)\b[^.\n]{0,60}\b(?:user-agent|x-[a-z0-9-]{2,}|header)\b",
            re.I,
        ),
        "required header",
    ),
    (re.compile(r"@(?:bugcrowdninja\.com|wearehackerone\.com|intigriti\.me|yeswehack\.ninja)\b", re.I), "test account"),
    (re.compile(r"\b(?:denial[- ]of[- ]service|DoS|DDoS)\b", re.I), "no DoS"),
]


def extract_conduct(text: str) -> list[str]:
    """Researcher-conduct sentences (rate limits, required headers, automation bans, test-account
    domains, DoS clauses) from program text."""
    out, seen = [], set()
    for raw in re.split(r"(?<=[.!?])\s+|\n+", str(text or "")):
        sent = _one_line(raw.strip(" -*•#>"), 220)
        if len(sent) < 8:
            continue
        for rx, tag in _CONDUCT:
            if rx.search(sent):
                if sent.lower() not in seen:
                    seen.add(sent.lower())
                    out.append(f"{tag}: {sent}")
                break
    return out[:25]


# ================================================================================================
# Program references and bounty-targets-data
# ================================================================================================
def parse_ref(ref: str) -> tuple[str, str]:
    """``h1:acme`` / ``bugcrowd:acme`` / a program URL -> (platform, handle)."""
    ref = ref.strip()
    if "://" in ref:
        u = urllib.parse.urlparse(ref)
        host = (u.hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        plat = PLATFORM_HOSTS.get(host)
        if not plat:
            raise ValueError(f"not a program page on a platform bountyproof knows: {host or ref}")
        drop = {"programs", "engagements", "detail", "bug-bounty", "researcher"}
        parts = [x for x in u.path.split("/") if x and x.lower() not in drop]
        if not parts:
            raise ValueError(f"no program handle in the URL: {ref}")
        handle = "/".join(parts[-2:]) if plat == "intigriti" and len(parts) >= 2 else parts[-1]
        return plat, handle
    plat, sep, handle = ref.partition(":")
    if not sep or not handle.strip():
        raise ValueError(
            "a program reference looks like h1:<handle>, bugcrowd:<handle>, intigriti:<handle>, "
            "yeswehack:<handle>, or the program's URL"
        )
    if plat.lower() not in PLATFORMS:
        raise ValueError(f"unknown platform {plat!r}; use one of: {', '.join(sorted(PLATFORMS))}")
    return PLATFORMS[plat.lower()], handle.strip()


def _record_handle(platform: str, rec: dict) -> str:
    if platform == "hackerone":
        return rec.get("handle") or ""
    if platform == "intigriti":
        return f"{rec.get('company_handle', '')}/{rec.get('handle', '')}".strip("/")
    if platform == "yeswehack":
        return rec.get("id") or ""
    parts = [x for x in urllib.parse.urlparse(rec.get("url") or "").path.split("/") if x]
    return parts[-1] if parts else _one_line(rec.get("name") or "", 60)


def _record_keys(platform: str, rec: dict) -> set[str]:
    keys = {_record_handle(platform, rec).lower()}
    if platform == "intigriti":
        keys |= {str(rec.get("handle") or "").lower(), str(rec.get("company_handle") or "").lower()}
    if rec.get("url"):
        keys.add(rec["url"].rstrip("/").lower())
    keys.discard("")
    return keys


def find_program(platform: str, data: list, handle: str) -> dict:
    want = handle.strip().rstrip("/").lower()
    hits = [rec for rec in data if want in _record_keys(platform, rec)]
    if platform == "intigriti" and len(hits) > 1:  # a company with several programs
        exact = [
            r for r in hits if _record_handle(platform, r).lower() == want or str(r.get("handle") or "").lower() == want
        ]
        hits = exact or hits
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        names = ", ".join(_record_handle(platform, r) for r in hits[:8])
        raise LookupError(f"{handle!r} matches several {platform} programs: {names}")
    pool = sorted({_record_handle(platform, r) for r in data})
    close = difflib.get_close_matches(handle, pool, n=5, cutoff=0.6)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    raise LookupError(
        f"no public {platform} program {handle!r} in bounty-targets-data.{hint} For a private program, "
        "paste the scope from its page into a file and use --text."
    )


def cache_dir() -> Path:
    return profile.home() / "cache" / "bounty-targets"


def load_platform(
    platform: str, refresh: bool = False, cache: Path | None = None, opener=None, log=None
) -> tuple[list, Path]:
    """The platform's bounty-targets-data dump, cached for CACHE_MAX_AGE seconds (never in the repo)."""
    cache = cache or cache_dir()
    path = cache / f"{platform}_data.json"
    fresh = path.exists() and time.time() - path.stat().st_mtime < CACHE_MAX_AGE
    if refresh or not fresh:
        url = SOURCE_URL.format(platform=platform)
        try:
            body = _download(url, opener or urllib.request.urlopen)
            json.loads(body)  # never cache a broken body
            cache.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=cache, suffix=".part")
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
            os.replace(tmp, path)
        except Exception as err:  # noqa: BLE001 - fall back to a stale cache
            if not path.exists():
                raise ScopeImportError(f"could not download {url}: {err}") from err
            if log:
                log(f"warning: refresh failed ({err}); using the cached {path}")
    with path.open(encoding="utf-8") as fh:
        return json.load(fh), path


def _download(url: str, opener) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with opener(req, timeout=FETCH_TIMEOUT) as resp:
        body = resp.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise ScopeImportError(f"response larger than {MAX_DOWNLOAD} bytes")
    return body


# ================================================================================================
# Program -> notes/scope.json
# ================================================================================================
@dataclass
class Result:
    scope: dict
    imported_in: list[str]
    imported_out: list[str]
    kept_in: list[str]
    kept_out: list[str]
    review: list[dict]
    other: list[dict]
    conflicts: list[str]
    whitebox: bool
    changed: bool  # the confirmation hash changed


def _strings(v: object) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def apply(current: dict, p: Program, *, whitebox: bool = False, today: str | None = None) -> Result:
    """``current`` (the workspace's scope.json) refreshed with ``p``. Rules the last import wrote are
    replaced; rules written by hand are kept."""
    imp_in, imp_out = p.rules("in"), p.rules("out")
    if whitebox:  # lab only: every program asset is off limits
        imp_out = list(dict.fromkeys(imp_in + imp_out))
        imp_in = []
    prev = current.get("_import") if isinstance(current.get("_import"), dict) else {}
    hand_in = [x for x in _strings(current.get("inScope")) if x not in set(_strings(prev.get("inScope")))]
    hand_out = [x for x in _strings(current.get("outOfScope")) if x not in set(_strings(prev.get("outOfScope")))]
    new = dict(current)
    new["inScope"] = list(dict.fromkeys(imp_in + hand_in))
    new["outOfScope"] = list(dict.fromkeys(imp_out + hand_out))
    new["needsReview"] = p.review()
    new["_needsReview_note"] = (
        "Listed by the program but NOT rules: the guard can't enforce them as written. Read "
        "each one and, if you need it, write the rule in inScope/outOfScope yourself."
    )
    new["otherAssets"] = p.other()
    new["_import"] = {
        "source": p.source,
        "program": f"{p.platform}:{p.handle}" if p.platform != "text" else p.handle,
        "url": p.url,
        "date": today or dt.date.today().isoformat(),
        "mode": "whitebox" if whitebox else "blackbox",
        "inScope": imp_in,
        "outOfScope": imp_out,
        "conduct": p.conduct,
        "exclusions": p.exclusions,
        "_note": "What `bountyproof scope import` wrote last. A re-import replaces these rules and keeps the rest.",
    }
    out_set = set(imp_out)
    conflicts = [x for x in hand_in if x in out_set]
    return Result(
        new,
        imp_in,
        imp_out,
        hand_in,
        hand_out,
        new["needsReview"],
        new["otherAssets"],
        conflicts,
        whitebox,
        scope.scope_hash(new) != scope.scope_hash(current),
    )


def is_whitebox(workspace: Path) -> bool:
    try:
        return "ENGAGEMENT MODE: WHITE-BOX" in (workspace / "CLAUDE.md").read_text(encoding="utf-8")
    except OSError:
        return False


def load_program(
    ref: str | None,
    *,
    text: str | None = None,
    name: str | None = None,
    data: Path | None = None,
    refresh: bool = False,
    log=None,
) -> Program:
    """The program from a reference (bounty-targets-data, or a local dump with ``data``) or pasted text."""
    if text is not None:
        p = program_from_text(text, name=name or "program")
        p.source = "pasted program text"
        return p
    if not ref:
        raise ValueError(
            "give a program reference (h1:<handle>, bugcrowd:, intigriti:, yeswehack: or the URL) or --text"
        )
    platform, handle = parse_ref(ref)
    if data:
        dump = json.loads(Path(data).read_text(encoding="utf-8"))
        records = dump if isinstance(dump, list) else [dump]
        where = str(data)
    else:
        records, path = load_platform(platform, refresh=refresh, log=log)
        where = f"bounty-targets-data ({path.name})"
    rec = find_program(platform, records, handle)
    p = program_from_record(platform, rec)
    p.source = where
    if platform == "hackerone" and rec.get("submission_state") not in (None, "open") and log:
        log(f"warning: the program's submission state is {rec.get('submission_state')!r}")
    return p
