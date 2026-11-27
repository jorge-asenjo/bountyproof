// The hook's side of the parity corpus: tests/test_scope_parity.py runs the same cases on the CLI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonHost, canonRule, classify, compileScope, ruleText } from '../hooks/scope-guard.mjs';

const CASES = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'scope-cases.json'), 'utf8'));

test('hosts: the host a client connects to, or a refusal', () => {
  for (const [input, want] of CASES.hosts) {
    const got = canonHost(input);
    const seen = got.local ? 'local' : got.problem ? null : got.host;
    assert.equal(seen, want, `${JSON.stringify(input)} -> ${JSON.stringify(got)}`);
  }
});

test('rules: one canonical form, and it reads back as the same rule', () => {
  for (const [input, side, want] of CASES.rules) {
    const got = canonRule(input, side);
    const seen = got.problem ? null : ruleText(got.rule);
    assert.equal(seen, want, `${JSON.stringify(input)} (${side}) -> ${JSON.stringify(got.problem || seen)}`);
    if (seen !== null) assert.equal(ruleText(canonRule(seen, side).rule), seen, `round trip of ${seen}`);
  }
});

test('classify: out of scope first, then in scope, unlisted, allowed, unknown', () => {
  const compiled = compileScope(CASES.classify.scope);
  assert.deepEqual(compiled.errors, []);
  for (const [dest, want] of CASES.classify.cases) {
    const h = canonHost(dest);
    assert.ok(h.host, `${dest} has a host`);
    assert.equal(classify(h.host, compiled), want, dest);
  }
});

test('files: which scope.json the guard can enforce, and when it is live', () => {
  for (const [raw, valid, active] of CASES.files) {
    const c = compileScope(raw);
    assert.equal(c.errors.length === 0, valid, `${JSON.stringify(raw)}: ${c.errors.join('; ')}`);
    assert.equal(c.active, active, `${JSON.stringify(raw)} active`);
  }
});
