import { test } from "node:test";
import assert from "node:assert/strict";
import scrubDefault, { scrub, scan, hasSecrets, createScrubber, luhn, normaliseKey, PATTERNS } from "../dist/index.js";
import * as F from "./fixtures.mjs";

const R = "[REDACTED]";

test("default export is scrub", () => assert.equal(scrubDefault, scrub));

test("each built-in detector catches its format and nothing else survives", () => {
  const cases = {
    "aws-access-key-id": F.AWS_ID, "github-token": F.GITHUB, "npm-token": F.NPM, "slack-token": F.SLACK,
    "stripe-key": F.STRIPE, "google-api-key": F.GOOGLE, "anthropic-key": F.ANTHROPIC, "openai-key": F.OPENAI,
    "sendgrid-key": F.SENDGRID, jwt: F.JWT, "private-key": F.PRIVATE_KEY, "credit-card": F.CARD,
  };
  for (const [type, secret] of Object.entries(cases)) {
    const text = `before ${secret} after`;
    assert.equal(scrub(text), `before ${R} after`, type);
    assert.deepEqual(scan(text).map((f) => f.type), [type], type);
  }
  assert.equal(scrub(`pat ${F.GITHUB_PAT} x`), `pat ${R} x`);
});

test("context-preserving detectors keep the prefix", () => {
  assert.equal(scrub("Authorization: Bearer abcdefghijklmnop.qrstuv"), `Authorization: Bearer ${R}`);
  assert.equal(scrub("Basic dXNlcjpwYXNzd29yZA=="), `Basic ${R}`);
  assert.equal(scrub("db: postgres://admin:s3cr3t-pw@db.internal:5432/app"), `db: postgres://admin:${R}@db.internal:5432/app`);
  assert.equal(scrub("password=hunter2 user=bob"), `password=${R} user=bob`);
  assert.equal(scrub('{"api_key": "abc123", "name": "x"}'), `{"api_key": "${R}", "name": "x"}`);
  assert.equal(scrub("API-KEY: abc-123"), `API-KEY: ${R}`);
  assert.equal(scrub("token = 'xyz'"), `token = '${R}'`);
});

test("key-value detector skips placeholders and already-redacted values", () => {
  assert.equal(scrub("password=null token=undefined secret=[REDACTED] pwd=****"), "password=null token=undefined secret=[REDACTED] pwd=****");
  assert.equal(scrub("author: Jane"), "author: Jane");
  assert.equal(scrub("tokens: 15"), "tokens: 15");
});

test("credit card requires Luhn, 13–19 digits", () => {
  assert.equal(scrub(`card ${F.CARD_BAD_LUHN}`), `card ${F.CARD_BAD_LUHN}`);
  assert.equal(scrub("order 123456789012"), "order 123456789012");
  assert.equal(scrub("5500-0000-0000-0004"), R);
  assert.ok(luhn("4111111111111111"));
  assert.ok(!luhn("4111111111111112"));
});

test("optional detectors are off by default and can be enabled", () => {
  const t = "mail jane@example.com from 10.0.0.1";
  assert.equal(scrub(t), t);
  assert.equal(scrub(t, { enable: ["email"] }), `mail ${R} from 10.0.0.1`);
  assert.equal(scrub(t, { enable: ["email", "ipv4"] }), `mail ${R} from ${R}`);
  assert.equal(scrub(`${F.JWT}`, { disable: ["jwt"] }), F.JWT);
});

test("tag, reveal, custom replacement, function replacement", () => {
  assert.equal(scrub(`x ${F.NPM}`, { tag: true }), "x [REDACTED:npm-token]");
  assert.equal(scrub(`x ${F.NPM}`, { reveal: 4 }), `x [REDACTED…${F.NPM.slice(-4)}]`);
  assert.equal(scrub(`x ${F.NPM}`, { tag: true, reveal: 2 }), `x [REDACTED:npm-token…${F.NPM.slice(-2)}]`);
  assert.equal(scrub(`x ${F.NPM}`, { replacement: "***" }), "x ***");
  assert.equal(scrub(`x ${F.NPM}`, { replacement: "***", tag: true }), "x ***:npm-token");
  assert.equal(scrub(`x ${F.NPM}`, { replacement: (s, t) => `<${t}:${s.length}>` }), "x <npm-token:40>");
});

test("multiple and overlapping secrets in one string", () => {
  const text = `Bearer ${F.JWT} and key ${F.AWS_ID} and ${F.GITHUB}`;
  const out = scrub(text);
  assert.equal(out, `Bearer ${R} and key ${R} and ${R}`);
  assert.equal(scan(text).length, 3);
  // Bearer prefix + JWT: the JWT detector wins (earlier), the auth-header one must not double-redact.
  assert.deepEqual(scan(`Bearer ${F.JWT}`).map((f) => f.type), ["jwt"]);
});

test("custom patterns run first", () => {
  const out = scrub("ticket ACME-12345 ok", { patterns: [{ type: "acme", regex: /\bACME-\d+\b/g }] });
  assert.equal(out, `ticket ${R} ok`);
  assert.throws(() => scrub("x", { patterns: [{ type: "bad", regex: /x/ }] }), TypeError);
});

test("objects: sensitive keys redacted wholesale, other strings scanned, input not mutated", () => {
  const input = {
    user: "bob",
    password: "hunter2",
    accessToken: "abc",
    apiKey: 12345,
    enabled: true,
    nothing: null,
    headers: { Authorization: `Bearer ${F.JWT}`, "X-Api-Key": "k", "content-type": "json" },
    note: `see ${F.AWS_ID}`,
    list: [F.GITHUB, "plain", { refresh_token: "r" }],
    credentials: { username: "u", pass: "p", nested: ["a", 1] },
  };
  const snapshot = JSON.stringify(input);
  const out = scrub(input);
  assert.deepEqual(out, {
    user: "bob",
    password: R,
    accessToken: R,
    apiKey: R,
    enabled: true,
    nothing: null,
    headers: { Authorization: R, "X-Api-Key": R, "content-type": "json" },
    note: `see ${R}`,
    list: [R, "plain", { refresh_token: R }],
    credentials: { username: R, pass: R, nested: [R, R] },
  });
  assert.equal(JSON.stringify(input), snapshot);
});

test("objects: keys and ignoreKeys options", () => {
  const input = { ssn: "1", licence: "L1", password: "p" };
  assert.deepEqual(scrub(input, { keys: ["licence"] }), { ssn: R, licence: R, password: R });
  assert.deepEqual(scrub(input, { ignoreKeys: ["ssn"] }), { ssn: "1", licence: "L1", password: R });
});

test("objects: Error, Map, Set, Date, circular, depth limit", () => {
  const err = new Error(`failed with ${F.NPM}`);
  err.token = "t";
  const e = scrub(err);
  assert.equal(e.message, `failed with ${R}`);
  assert.equal(e.token, R);
  assert.equal(typeof e.stack, "string");

  const m = scrub(new Map([["password", "x"], ["note", F.GITHUB]]));
  assert.deepEqual([...m], [["password", R], ["note", R]]);
  assert.deepEqual([...scrub(new Set([F.GITHUB, "ok"]))], [R, "ok"]);

  const d = new Date(0);
  assert.equal(scrub({ d }).d, d);

  const circ = { name: "a" };
  circ.self = circ;
  assert.equal(scrub(circ).self, "[CIRCULAR]");

  let deep = { v: F.GITHUB };
  for (let i = 0; i < 40; i++) deep = { child: deep };
  assert.match(JSON.stringify(scrub(deep)), /DEPTH LIMIT/);
  assert.doesNotMatch(JSON.stringify(scrub(deep)), new RegExp(F.GITHUB));
});

test("scan reports paths and offsets, never values; hasSecrets", () => {
  const findings = scan({ password: "p", note: `k ${F.AWS_ID}`, arr: [F.NPM] });
  assert.deepEqual(findings, [
    { type: "key", path: "password" },
    { type: "aws-access-key-id", path: "note", start: 2, end: 2 + F.AWS_ID.length },
    { type: "npm-token", path: "arr.0", start: 0, end: F.NPM.length },
  ]);
  assert.doesNotMatch(JSON.stringify(findings), /AKIA|npm_/);
  assert.equal(hasSecrets("nothing here"), false);
  assert.equal(hasSecrets({ a: { b: { token: "x" } } }), true);
  assert.deepEqual(scan("plain"), []);
});

test("createScrubber binds options", () => {
  const s = createScrubber({ tag: true, enable: ["email"] });
  assert.equal(s.scrub("a@b.co"), "[REDACTED:email]");
  assert.equal(s.hasSecrets("a@b.co"), true);
  assert.equal(s.scan("a@b.co")[0].type, "email");
});

test("normaliseKey and PATTERNS metadata", () => {
  assert.equal(normaliseKey("accessToken"), "access_token");
  assert.equal(normaliseKey("X-Api-Key"), "x_api_key");
  assert.equal(normaliseKey("client secret"), "client_secret");
  assert.ok(PATTERNS.every((p) => p.regex.global));
  assert.ok(PATTERNS.some((p) => p.type === "email" && p.optional));
});

test("non-string primitives pass through", () => {
  assert.equal(scrub(42), 42);
  assert.equal(scrub(null), null);
  assert.equal(scrub(undefined), undefined);
  assert.equal(scrub(true), true);
});
