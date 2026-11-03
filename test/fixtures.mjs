// Every value here is fake. Shapes are real so the detectors fire; none of these are live credentials.
// They are assembled at runtime so no literal in this file looks like a secret to scanners.
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const letters = "abcdefghijklmnopqrstuvwxyz";
const alnum = (n) => Array.from({ length: n }, (_, i) => (letters + "0123456789")[i % 36]).join("");
const digits = (n) => "0".repeat(n);

export const JWT = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "123", name: "test user" })}.${alnum(30)}`;
export const AWS_ID = ["AKIA", "IOSFODNN7", "EXAMPLE"].join(""); // AWS's own documentation example key id
export const GITHUB = ["gh", "p_", alnum(36)].join("");
export const GITHUB_PAT = ["github", "_pat_", alnum(30)].join("");
export const NPM = ["npm", "_", alnum(36)].join("");
export const SLACK = ["xox", "b-", digits(12), "-", digits(12), "-", alnum(24)].join("");
export const STRIPE = ["sk_", "test_", "EXAMPLE", alnum(20)].join("");
export const GOOGLE = ["AI", "za", "Sy", alnum(33)].join(""); // 35 chars after the prefix
export const ANTHROPIC = ["sk-", "ant-", "api03-EXAMPLE", alnum(24)].join("");
export const OPENAI = ["sk-", "proj-", "EXAMPLE", alnum(30)].join("");
export const SENDGRID = ["SG", ".", alnum(22), ".", alnum(43)].join("");
export const CARD = "4111 1111 1111 1111"; // standard Visa test number
export const CARD_BAD_LUHN = "4111 1111 1111 1112";
export const PRIVATE_KEY = ["-----BEGIN RSA ", "PRIVATE KEY-----", "\nMIIEowIBAAKCAQEAfake\nmorefake==\n", "-----END RSA ", "PRIVATE KEY-----"].join("");
