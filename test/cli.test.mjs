import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as F from "./fixtures.mjs";

const CLI = resolve("dist/cli.js");
const run = (args, input = "") => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", input });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test("scrubs stdin to stdout, preserving everything else byte for byte", () => {
  const input = `line1\npassword=abc\n${F.JWT}\nline4 no newline`;
  const r = run([], input);
  assert.equal(r.code, 0);
  assert.equal(r.out, "line1\npassword=[REDACTED]\n[REDACTED]\nline4 no newline");
});

test("file arguments and dash for stdin", () => {
  const dir = mkdtempSync(join(tmpdir(), "scrub-"));
  const f = join(dir, "app.log");
  writeFileSync(f, `key ${F.AWS_ID}\n`);
  assert.equal(run([f]).out, "key [REDACTED]\n");
  assert.equal(run(["-"], "x").out, "x");
  const miss = run([join(dir, "missing.log")]);
  assert.equal(miss.code, 2);
  assert.match(miss.err, /ENOENT|no such file/i);
});

test("--tag, --reveal, --replacement, --enable, --disable", () => {
  assert.equal(run(["--tag"], F.NPM).out, "[REDACTED:npm-token]");
  assert.equal(run(["-r", "3"], F.NPM).out, `[REDACTED…${F.NPM.slice(-3)}]`);
  assert.equal(run(["--replacement", "XXX"], F.NPM).out, "XXX");
  assert.equal(run(["--enable", "email"], "a@b.co").out, "[REDACTED]");
  assert.equal(run(["--disable", "jwt"], F.JWT).out, F.JWT);
  assert.equal(run(["--enable", "nope"]).code, 2);
  assert.equal(run(["-r", "x"]).code, 2);
});

test("--json scrubs object keys", () => {
  const r = run(["--json"], JSON.stringify({ password: "p", msg: `k ${F.GITHUB}`, ok: 1 }));
  assert.equal(r.code, 0);
  assert.deepEqual(JSON.parse(r.out), { password: "[REDACTED]", msg: "k [REDACTED]", ok: 1 });
  assert.equal(run(["--json"], "{not json").code, 2);
});

test("--check reports counts, exits 1 on findings, prints nothing sensitive", () => {
  const r = run(["--check"], `a ${F.JWT} b ${F.JWT} c password=x`);
  assert.equal(r.code, 1);
  assert.match(r.out, /Found 3 secret\(s\):\n  jwt: 2\n  key-value: 1\n/);
  assert.doesNotMatch(r.out, /eyJ/);
  const clean = run(["--check"], "nothing");
  assert.equal(clean.code, 0);
  assert.match(clean.out, /No secrets found/);
});

test("--list, --help, --version, unknown option", () => {
  assert.match(run(["--list"]).out, /^private-key\n/);
  assert.match(run(["--list"]).out, /email \(optional\)/);
  assert.equal(run(["--help"]).code, 0);
  assert.match(run(["-v"]).out, /^\d+\.\d+\.\d+\n$/);
  assert.equal(run(["--wat"]).code, 2);
});
