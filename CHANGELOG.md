# Changelog

## 1.0.1 (2026-11-16)

- Fix: the CLI read all of stdin before writing anything, so a live stream such as `tail -f app.log | scrub-secrets` printed nothing until the stream ended. Stdin is now scrubbed and written line by line. A private key block is held until its END line so it is still redacted as a whole.
- The CLI exits quietly when the reader closes the pipe (`| head`).

## 1.0.0 (2026-11-03)

- Initial release: `scrub`, `scan`, `hasSecrets`, `createScrubber`.
- 16 built-in detectors plus optional email and IPv4, sensitive-key redaction for objects, custom patterns.
- CLI `scrub-secrets` for pipes and files, with `--check` for CI.
- ESM and CommonJS builds with TypeScript types. Node 18+.
