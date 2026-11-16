# scrub-secrets

[![npm version](https://img.shields.io/npm/v/scrub-secrets.svg)](https://www.npmjs.com/package/scrub-secrets)
[![CI](https://github.com/amirshahzadhashmi7145/scrub-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/amirshahzadhashmi7145/scrub-secrets/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/scrub-secrets.svg)](./LICENSE)

Redact API keys, tokens, JWTs, private keys, passwords and card numbers from strings and objects before they reach a log, a ticket, or a chat message. Zero dependencies, typed, with a CLI that works in a pipe.

```js
import { scrub } from "scrub-secrets";

scrub("Authorization: Bearer eyJhbGciOi...");
// "Authorization: Bearer [REDACTED]"

scrub({ user: "bob", password: "hunter2", headers: { "x-api-key": "k" }, note: "see AKIAIOSFODNN7EXAMPLE" });
// { user: "bob", password: "[REDACTED]", headers: { "x-api-key": "[REDACTED]" }, note: "see [REDACTED]" }
```

```sh
kubectl logs my-pod | npx scrub-secrets
```

## Install

```sh
npm install scrub-secrets
```

Node 18 or newer. ESM and CommonJS, TypeScript types included.

## What it catches

Two mechanisms work together.

**Pattern detectors** scan every string:

| Type | Example shape |
|---|---|
| `private-key` | `-----BEGIN RSA PRIVATE KEY-----` … `-----END RSA PRIVATE KEY-----` |
| `aws-access-key-id` | `AKIA…` and other AWS key-id prefixes |
| `github-token` | `ghp_…`, `gho_…`, `github_pat_…` |
| `npm-token` | `npm_…` |
| `slack-token` | `xoxb-…`, `xoxp-…` |
| `stripe-key` | `sk_live_…`, `sk_test_…`, `rk_live_…` |
| `google-api-key` | `AIza…` |
| `anthropic-key` | `sk-ant-…` |
| `openai-key` | `sk-…`, `sk-proj-…` |
| `sendgrid-key` | `SG.xxx.yyy` |
| `twilio-key` | `SK` + 32 hex |
| `jwt` | `eyJ….eyJ….sig` |
| `auth-header` | `Bearer xxx`, `Basic xxx`. The scheme word is kept. |
| `url-password` | `postgres://user:PASSWORD@host`. Only the password goes. |
| `key-value` | `password=…`, `"api_key": "…"`, `token: …` in free text. The key is kept. |
| `credit-card` | 13 to 19 digits with spaces or dashes, validated with Luhn. |
| `email` | Optional, off by default. |
| `ipv4` | Optional, off by default. |

**Sensitive object keys** are redacted wholesale when scrubbing objects: `password`, `secret`, `token`, `apiKey`, `api_key`, `x-api-key`, `authorization`, `cookie`, `accessToken`, `refresh_token`, `private_key`, `client_secret`, `credentials`, `ssn`, `cvv`, `otp`, `pin`, and so on. Matching is case-insensitive and understands camelCase, snake_case and kebab-case. Objects under a sensitive key have every leaf redacted.

Values are never mutated. `scrub` always returns a copy.

## API

### `scrub(input, options?)`

Returns a redacted copy of a string, object, array, `Error`, `Map` or `Set`. Other values pass through.

| Option | Default | Description |
|---|---|---|
| `replacement` | `"[REDACTED]"` | Replacement string, or `(secret, type) => string`. |
| `tag` | `false` | Append the detector type: `[REDACTED:jwt]`. |
| `reveal` | `0` | Keep the last n characters: `[REDACTED…x9Qz]`. Handy for telling keys apart. |
| `enable` | `[]` | Turn on optional detectors: `["email", "ipv4"]`. |
| `disable` | `[]` | Turn off detectors by type. |
| `patterns` | `[]` | Extra detectors, run before the built-ins. See below. |
| `keys` | `[]` | Extra object keys to redact wholesale. |
| `ignoreKeys` | `[]` | Object keys never redacted wholesale. Their strings are still scanned. |
| `maxDepth` | `32` | Nesting limit. Deeper values become `"[DEPTH LIMIT]"`. |

Circular references become `"[CIRCULAR]"`.

### `scan(input, options?)`

Tells you where the secrets are without returning their values. For a string you get `{ type, start, end }`. For an object you get `{ type, path }`, with `type: "key"` for a sensitive key hit.

```js
scan({ password: "p", note: "key AKIAIOSFODNN7EXAMPLE" });
// [ { type: "key", path: "password" },
//   { type: "aws-access-key-id", path: "note", start: 4, end: 24 } ]
```

### `hasSecrets(input, options?)`

Boolean shortcut over `scan`. Useful as a test assertion on log output.

### `createScrubber(options)`

Returns `{ scrub, scan, hasSecrets }` with the options baked in.

### Custom detectors

```js
scrub(text, {
  patterns: [
    { type: "acme-id", regex: /\bACME-\d{6}\b/g },
    { type: "internal-token", regex: /(X-Internal:\s*)(\S+)/g, group: 2 },
  ],
});
```

A pattern needs a `type`, a global `regex`, and optionally a `group` number for which capture holds the secret, a `validate(secret)` function, and `optional: true` to make it off by default. `PATTERNS`, `luhn` and `normaliseKey` are exported too.

## Recipes

Wrap a logger:

```js
import pino from "pino";
import { createScrubber } from "scrub-secrets";

const { scrub } = createScrubber({ tag: true });
const logger = pino({ hooks: { logMethod(args, method) { method.apply(this, args.map((a) => scrub(a))); } } });
```

Assert in tests that nothing leaked:

```js
import { hasSecrets } from "scrub-secrets";
assert.equal(hasSecrets(capturedLogs), false);
```

Scrub an error before sending it to an error tracker:

```js
reporter.capture(scrub(err));
```

## CLI

```
scrub-secrets [options] [file...]

  -t, --tag              Include the detector type, e.g. [REDACTED:jwt]
  -r, --reveal <n>       Keep the last n characters visible
      --replacement <s>  Replacement text
      --enable <types>   Enable optional detectors (email, ipv4)
      --disable <types>  Disable detectors
      --json             Treat input as JSON and scrub it as an object
      --check            Count secrets per type, exit 1 if any. Prints nothing sensitive.
      --list             List detector types
```

```sh
# Pipe anything through it
docker logs api 2>&1 | npx scrub-secrets

# Follow a live log; output is written line by line
tail -f app.log | scrub-secrets

# Scrub a file before attaching it to a ticket
npx scrub-secrets app.log > app.scrubbed.log

# Fail CI if a build log contains credentials
npx scrub-secrets --check build.log
```

Exit codes: `0` success, `1` when `--check` finds secrets, `2` on bad input.

## Limits

Pattern matching catches known formats and obvious key-value pairs. A random high-entropy string with no recognisable shape will not be caught. Treat this as a safety net, not a guarantee, and keep real secrets out of logs at the source.

## License

MIT
