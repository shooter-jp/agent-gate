import { createHash } from "node:crypto";

const secretKeyPattern =
  /(?:api[_-]?key|token|secret|password|passwd|authorization|auth|credential|private[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|session[_-]?cookie|cookie)/i;

const stringSecretPatterns: RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/g,
  /\bsk-[A-Za-z0-9_-]{10,}\b/g,
  /\bghp_[A-Za-z0-9_]{10,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{10,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g
];

export function redactString(value: string): string {
  return stringSecretPatterns.reduce((text, pattern) => text.replace(pattern, "[REDACTED]"), value);
}

export function redactValue(value: unknown): unknown {
  if (typeof value === "string") return redactString(value);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => redactValue(item));

  const output: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    output[key] = secretKeyPattern.test(key) ? "[REDACTED]" : redactValue(nested);
  }
  return output;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => sortValue(item));
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, nested]) => [key, sortValue(nested)])
  );
}

export function hashResult(value: unknown): string {
  const redacted = redactValue(value);
  return hashCanonicalValue(redacted);
}

export function hashCanonicalValue(value: unknown): string {
  const digest = createHash("sha256").update(canonicalJson(value)).digest("hex");
  return `sha256:${digest}`;
}

export function redactedExcerpt(value: unknown, maxLength = 240): string {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const redacted = redactString(text ?? "");
  return redacted.length > maxLength ? `${redacted.slice(0, maxLength - 3)}...` : redacted;
}
