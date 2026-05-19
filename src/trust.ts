import { minimatch } from "minimatch";
import { redactedExcerpt } from "./redaction";
import type { TrustEvidence, TrustState } from "./types";

export const suspiciousPatterns = [
  "ignore previous instructions",
  "ignore all previous instructions",
  "system prompt",
  "developer message",
  "reveal secrets",
  "exfiltrate",
  "send to",
  "post to webhook",
  "base64",
  "do not tell the user",
  "hidden instruction"
];

export function createTrustState(): TrustState {
  return {
    tainted: false,
    sources: []
  };
}

export function cloneTrustState(state: TrustState): TrustState {
  return {
    tainted: state.tainted,
    sources: state.sources.map((source) => ({ ...source }))
  };
}

export function toolMatchesAny(tool: string, patterns: string[]): string | undefined {
  return patterns.find((pattern) => tool === pattern || minimatch(tool, pattern));
}

export function updateTrustFromResult(
  state: TrustState,
  tool: string,
  result: unknown,
  untrustedPatterns: string[]
): { before: TrustState; after: TrustState; evidence: TrustEvidence[] } {
  const before = cloneTrustState(state);
  const evidence: TrustEvidence[] = [];
  const untrustedPattern = toolMatchesAny(tool, untrustedPatterns);

  if (untrustedPattern) {
    evidence.push({
      tool,
      reason: `tool matched untrusted pattern ${untrustedPattern}`,
      evidence: `tool matched untrusted pattern ${untrustedPattern}`
    });
  }

  const suspiciousPattern = findSuspiciousPattern(result);
  if (suspiciousPattern) {
    evidence.push({
      tool,
      reason: `result contained suspicious pattern: ${suspiciousPattern}`,
      evidence: extractEvidence(result, suspiciousPattern)
    });
  }

  const after = cloneTrustState(state);
  if (evidence.length > 0) {
    after.tainted = true;
    after.sources = appendEvidence(after.sources, evidence);
  }

  return { before, after, evidence };
}

function appendEvidence(existing: TrustEvidence[], additions: TrustEvidence[]): TrustEvidence[] {
  const output = [...existing];
  for (const item of additions) {
    if (
      !output.some(
        (existingItem) => existingItem.tool === item.tool && existingItem.reason === item.reason
      )
    ) {
      output.push(item);
    }
  }
  return output;
}

function findSuspiciousPattern(result: unknown): string | undefined {
  const text = stringifyForInspection(result).toLowerCase();
  return suspiciousPatterns.find((pattern) => text.includes(pattern));
}

function extractEvidence(result: unknown, pattern: string): string {
  const text = stringifyForInspection(result);
  const lower = text.toLowerCase();
  const index = lower.indexOf(pattern);
  if (index === -1) return redactedExcerpt(text);
  const start = Math.max(0, index - 80);
  const end = Math.min(text.length, index + pattern.length + 160);
  return redactedExcerpt(text.slice(start, end));
}

function stringifyForInspection(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
