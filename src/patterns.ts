export interface Pattern {
  /** Short identifier, e.g. "github-token". */
  type: string;
  /** Must use the global flag. */
  regex: RegExp;
  /**
   * Which capture group holds the secret. 0 (default) means the whole match.
   * Other groups are kept verbatim so context like "Bearer " or "password=" survives.
   */
  group?: number;
  /** Extra validation on the captured secret. Return false to leave it alone. */
  validate?: (secret: string) => boolean;
  /** Off unless enabled explicitly, for patterns with high false-positive rates. */
  optional?: boolean;
}

/** Luhn checksum used to confirm a digit run is really a card number. */
export function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

const KEY_NAMES =
  "password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth|authorization|credentials?|session[_-]?id|refresh[_-]?token|access[_-]?token|id[_-]?token|bearer|cookie|otp|cvv|ssn";

/** Built-in detectors, applied in this order. Earlier matches win over later overlapping ones. */
export const PATTERNS: readonly Pattern[] = [
  {
    type: "private-key",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/g,
  },
  { type: "aws-access-key-id", regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b/g },
  { type: "github-token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g },
  { type: "npm-token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { type: "slack-token", regex: /\bxox[abeprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: "stripe-key", regex: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { type: "google-api-key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: "anthropic-key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { type: "openai-key", regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g },
  { type: "sendgrid-key", regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
  { type: "twilio-key", regex: /\bSK[0-9a-fA-F]{32}\b/g },
  { type: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  {
    type: "auth-header",
    regex: /(\b(?:Bearer|Basic|Token|Digest)\s+)([A-Za-z0-9._~+/=-]{8,})/g,
    group: 2,
  },
  {
    type: "url-password",
    regex: /(\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:@/]+:)([^\s@/]+)(?=@)/g,
    group: 2,
  },
  {
    type: "key-value",
    // Key, optional closing quote (JSON), separator, optional opening quote, then the value.
    regex: new RegExp(`(\\b(?:${KEY_NAMES})\\b["']?\\s*[=:]\\s*["']?)([^\\s"',;&]+)`, "gi"),
    group: 2,
    // Skip placeholders, already-redacted values, and auth scheme words ("Authorization: Bearer <token>"
    // is handled by the auth-header detector, which keeps the scheme visible).
    validate: (v) => v !== "" && !/^(?:null|undefined|true|false|none|\*+|\[REDACTED[^\]]*\]|bearer|basic|token|digest)$/i.test(v),
  },
  {
    type: "credit-card",
    regex: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (v) => {
      const digits = v.replace(/[ -]/g, "");
      return digits.length >= 13 && digits.length <= 19 && luhn(digits);
    },
  },
  { type: "email", regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, optional: true },
  { type: "ipv4", regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, optional: true },
];

/** Object keys whose values are redacted wholesale. Matched against a snake_case-normalised key. */
export const SENSITIVE_KEY = new RegExp(`(?:^|_)(?:${KEY_NAMES.replace(/\[_-\]\?/g, "_?")}|pin|card_?number|x_api_key|set_cookie)(?:$|_)`, "i");

/** "accessToken" -> "access_token", "X-Api-Key" -> "x_api_key". */
export function normaliseKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[-\s.]+/g, "_").toLowerCase();
}
