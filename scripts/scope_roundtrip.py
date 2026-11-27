"""Import every public program in bounty-targets-data and check the scopes the guard would enforce.

    python scripts/scope_roundtrip.py                  # the four platforms, downloaded (cached 6 h)
    python scripts/scope_roundtrip.py --refresh        # download them again
    python scripts/scope_roundtrip.py --data DIR       # dumps already on disk (<platform>_data.json)

Not part of CI: it reads ~20 MB of live data, so it runs by hand or once a week. The dumps are cached
under ~/.bountyproof/cache (BOUNTYPROOF_HOME), never in the repository. For every program it checks:

1. every rule the import writes reads back as the same rule (``scope.canon_rule``);
2. every exact in-scope host is in scope, every excluded host is out, and no subdomain or apex of an
   exact host gets in unless a wildcard of the program covers it;
3. importing the program again changes nothing;
4. the hook (Node) classifies all of those hosts exactly like the CLI (Python).

Exit code 1 if anything fails, with the first failures listed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from bountyproof import scope  # noqa: E402
from bountyproof import scope_import as si  # noqa: E402

PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "yeswehack")
PROBE = "zz-roundtrip-probe"
NODE_CLASSIFY = """
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const { canonHost, classify, compileScope } = await import(pathToFileURL(process.env.BP_HOOK).href);
const batch = JSON.parse(fs.readFileSync(process.env.BP_BATCH, 'utf8'));
const out = batch.map(({ scope, hosts }) => {
  const c = compileScope(scope);
  const cls = h => { const x = canonHost(h); return x.host ? classify(x.host, c) : 'PROBLEM'; };
  return { errors: c.errors.length, classes: hosts.map(cls) };
});
process.stdout.write(JSON.stringify(out));
"""


def probes(sc: dict) -> list[tuple[str, str]]:
    """(host, what it must be) for one imported scope. 'in', 'out', or 'not-in'."""
    rules_in = [scope.canon_rule(r, "in").rule for r in sc["inScope"]]
    rules_out = [scope.canon_rule(r, "out").rule for r in sc["outOfScope"]]
    wilds = [r.value for r in rules_in if r.kind == "wild"]
    excluded = {r.value for r in rules_out if r.kind in ("host", "ip")}
    checks = []
    for r in rules_out:
        if r.kind in ("host", "ip"):
            checks.append((r.value, "out"))
    for r in rules_in:
        if r.kind not in ("host", "ip") or r.value in excluded:
            continue
        checks.append((r.value, "in"))
        if r.kind == "host":
            sub = f"{PROBE}.{r.value}"
            if not any(sub.endswith("." + w) for w in wilds):
                checks.append((sub, "not-in"))  # an exact host has no subdomains
            apex = r.value.split(".", 1)[1] if r.value.count(".") > 1 else None
            if apex and not any(apex.endswith("." + w) for w in wilds) and apex not in {x.value for x in rules_in}:
                checks.append((apex, "not-in"))  # nor a parent it didn't list
    return checks


def check_program(platform: str, rec: dict) -> tuple[dict, list[str], list[tuple[str, str]], dict]:
    p = si.program_from_record(platform, rec)
    res = si.apply({}, p, today="2000-01-01")
    sc = res.scope
    name = f"{platform}:{p.handle}"
    fails = []
    for key, side in (("inScope", "in"), ("outOfScope", "out")):
        for text in sc[key]:
            c = scope.canon_rule(text, side)
            if not c.rule or c.rule.text != text:
                fails.append(f"{name}: {key} rule {text!r} doesn't read back as itself ({c.problem or c.rule.text})")
    again = si.apply(sc, p, today="2000-01-01").scope
    if again != sc:
        fails.append(f"{name}: importing it again changed the scope")
    compiled = scope.compile_scope(sc)
    if compiled.errors:
        fails.append(f"{name}: the imported scope is invalid: {compiled.errors[:2]}")
    checks = probes(sc)
    for host, want in checks:
        got = scope.classify(scope.canon_host(host).host or "", compiled)
        if (want == "in" and got != "IN_SCOPE") or (want != "in" and got == "IN_SCOPE"):
            fails.append(f"{name}: {host} is {got}, expected {want}")
    stats = {
        "in": len(res.imported_in),
        "out": len(res.imported_out),
        "unlisted": len(res.imported_unlisted),
        "review": len(res.review),
        "other": len(res.other),
    }
    return sc, fails, checks, stats


def node_classes(batch: list[dict]) -> list[dict] | None:
    node = shutil.which("node")
    if not node:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "batch.json"
        path.write_text(json.dumps(batch), encoding="utf-8")
        proc = subprocess.run(
            [node, "--input-type=module", "-e", NODE_CLASSIFY],
            env={**os.environ, "BP_HOOK": str(ROOT / "hooks" / "scope-guard.mjs"), "BP_BATCH": str(path)},
            capture_output=True,
            encoding="utf-8",
            timeout=600,
        )
    if proc.returncode:
        raise SystemExit(f"node failed: {proc.stderr[-2000:]}")
    return json.loads(proc.stdout)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--platform", action="append", choices=PLATFORMS, help="only these (default: all four)")
    ap.add_argument("--data", type=Path, help="a folder with <platform>_data.json dumps, instead of downloading")
    ap.add_argument("--refresh", action="store_true", help="download the dumps again")
    ap.add_argument("--no-node", action="store_true", help="skip the hook (Node) parity check")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    fails: list[str] = []
    batch, expected = [], []
    totals = {"programs": 0, "in": 0, "out": 0, "unlisted": 0, "review": 0, "other": 0, "checks": 0}
    for platform in args.platform or PLATFORMS:
        if args.data:
            records = json.loads((args.data / f"{platform}_data.json").read_text(encoding="utf-8"))
        else:
            records, _ = si.load_platform(platform, refresh=args.refresh, log=lambda m: print(m, file=sys.stderr))
        n = 0
        for rec in records:
            sc, f, checks, stats = check_program(platform, rec)
            fails += f
            n += 1
            for k, v in stats.items():
                totals[k] += v
            totals["checks"] += len(checks)
            compiled = scope.compile_scope(sc)
            hosts = [h for h, _ in checks]
            batch.append({"scope": sc, "hosts": hosts})
            expected.append((f"{platform}:{si._record_handle(platform, rec)}", hosts, [
                scope.classify(scope.canon_host(h).host or "", compiled) for h in hosts]))  # fmt: skip
        totals["programs"] += n
        print(f"{platform}: {n} programs")

    if not args.no_node:
        got = node_classes(batch)
        if got is None:
            print("node not found: parity with the hook not checked", file=sys.stderr)
        else:
            for (name, hosts, py), node in zip(expected, got, strict=True):
                if node["errors"]:
                    fails.append(f"{name}: the hook finds the imported scope invalid")
                for host, a, b in zip(hosts, py, node["classes"], strict=True):
                    if a != b:
                        fails.append(f"{name}: {host} is {a} in Python and {b} in the hook")

    print(
        f"{totals['programs']} programs: {totals['in']} in-scope, {totals['out']} out-of-scope and "
        f"{totals['unlisted']} deny-unlisted rules, "
        f"{totals['review']} entries for review, {totals['other']} other assets, {totals['checks']} host checks"
    )
    if fails:
        print(f"FAILED: {len(fails)} problems")
        for line in fails[:40]:
            print(f"  - {line}")
        return 1
    print("OK: every rule reads back as itself, no subdomain of an exact host gets in, Node and Python agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
