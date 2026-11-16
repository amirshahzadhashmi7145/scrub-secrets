import { readFileSync } from "node:fs";
import { scrub, scan, PATTERNS, type ScrubOptions } from "./index.js";

const HELP = `scrub-secrets: redact secrets from text before it reaches a log, ticket or chat.

Reads stdin (or files) and writes the scrubbed text to stdout.

Usage:
  scrub-secrets [options] [file...]
  some-command 2>&1 | scrub-secrets

Options:
  -t, --tag              Include the detector type, e.g. [REDACTED:jwt]
  -r, --reveal <n>       Keep the last n characters visible
      --replacement <s>  Replacement text (default: [REDACTED])
      --enable <types>   Enable optional detectors, comma-separated (email, ipv4)
      --disable <types>  Disable detectors, comma-separated
      --json             Treat input as JSON and scrub it as an object (keys included)
      --check            Report counts per detector type and exit 1 if any secret is found.
                         Prints nothing sensitive.
      --list             List detector types
  -h, --help             Show this help
  -v, --version          Show version

Exit codes:
  0  success (or --check found nothing)
  1  --check found secrets
  2  usage or input error
`;

function fail(message: string): never {
  process.stderr.write(`scrub-secrets: ${message}\n`);
  process.exit(2);
}

function readVersion(): string {
  try {
    return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version as string;
  } catch {
    return "unknown";
  }
}

function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "EAGAIN" || code === "EOF") return "";
    throw e;
  }
}

/** Longest run of text held back while waiting for a newline or the end of a private key block. */
const MAX_HOLD = 64 * 1024;

/**
 * Scrub stdin as it arrives, so live streams such as `tail -f app.log | scrub-secrets` produce output
 * line by line. Only complete lines are scrubbed, and an unfinished private key block is held until
 * its END line, so no secret is split across two writes.
 */
async function streamStdin(options: ScrubOptions): Promise<void> {
  const write = (text: string): Promise<void> =>
    new Promise((done) => {
      if (text === "" || process.stdout.write(text)) done();
      else process.stdout.once("drain", () => done());
    });
  process.stdout.on("error", (e: NodeJS.ErrnoException) => {
    if (e.code === "EPIPE") process.exit(0); // the reader went away, e.g. `| head`
    throw e;
  });

  let pending = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    pending += chunk as string;
    let cut = pending.lastIndexOf("\n") + 1;
    if (cut === 0 && pending.length >= MAX_HOLD) cut = pending.length; // a very long line: stop waiting
    const begin = pending.lastIndexOf("-----BEGIN ", cut);
    if (begin !== -1 && pending.length - begin < MAX_HOLD) {
      const end = pending.indexOf("-----END ", begin);
      if (end === -1 || end >= cut) cut = begin;
    }
    if (cut === 0) continue;
    await write(scrub(pending.slice(0, cut), options));
    pending = pending.slice(cut);
  }
  await write(scrub(pending, options));
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const options: ScrubOptions = {};
  const files: string[] = [];
  let json = false;
  let check = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) fail(`Missing value for ${a}`);
      return v;
    };
    switch (a) {
      case "-h": case "--help": process.stdout.write(HELP); process.exit(0);
      case "-v": case "--version": process.stdout.write(`${readVersion()}\n`); process.exit(0);
      case "-t": case "--tag": options.tag = true; break;
      case "-r": case "--reveal": {
        const n = Number(next());
        if (!Number.isInteger(n) || n < 0) fail("--reveal must be a non-negative integer");
        options.reveal = n;
        break;
      }
      case "--replacement": options.replacement = next(); break;
      case "--enable": options.enable = next().split(",").map((s) => s.trim()).filter(Boolean); break;
      case "--disable": options.disable = next().split(",").map((s) => s.trim()).filter(Boolean); break;
      case "--json": json = true; break;
      case "--check": check = true; break;
      case "--list":
        for (const p of PATTERNS) process.stdout.write(`${p.type}${p.optional ? " (optional)" : ""}\n`);
        process.exit(0);
      default:
        if (a.startsWith("-") && a !== "-") fail(`Unknown option: ${a}\n\n${HELP}`);
        files.push(a);
    }
  }

  const known = new Set(PATTERNS.map((p) => p.type));
  for (const t of [...(options.enable ?? []), ...(options.disable ?? [])]) {
    if (!known.has(t)) fail(`Unknown detector "${t}". Run --list to see them.`);
  }

  const fromStdin = files.length === 0 || (files.length === 1 && files[0] === "-");
  if (fromStdin && !json && !check) {
    await streamStdin(options);
    return;
  }

  let text: string;
  if (fromStdin) {
    text = readStdin();
  } else {
    try {
      text = files.map((f) => readFileSync(f, "utf8")).join("");
    } catch (e) {
      fail((e as Error).message);
    }
  }

  let input: unknown = text;
  if (json) {
    try {
      input = JSON.parse(text);
    } catch (e) {
      fail(`Invalid JSON input: ${(e as Error).message}`);
    }
  }

  if (check) {
    const findings = scan(input, options);
    const counts = new Map<string, number>();
    for (const f of findings) counts.set(f.type, (counts.get(f.type) ?? 0) + 1);
    if (findings.length === 0) {
      process.stdout.write("No secrets found.\n");
      process.exit(0);
    }
    process.stdout.write(`Found ${findings.length} secret(s):\n`);
    for (const [type, n] of [...counts].sort((a, b) => b[1] - a[1])) process.stdout.write(`  ${type}: ${n}\n`);
    process.exit(1);
  }

  const out = scrub(input, options);
  process.stdout.write(json ? `${JSON.stringify(out, null, 2)}\n` : (out as string));
}

main().catch((e) => {
  process.stderr.write(`scrub-secrets: ${(e as Error).message}\n`);
  process.exit(2);
});
