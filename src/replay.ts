import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import { loadConfig } from "./config";
import { evaluatePolicy } from "./policy";
import { hashCanonicalValue } from "./redaction";
import { readTraceFile } from "./trace";
import { cloneTrustState, createTrustState } from "./trust";
import type {
  ExpectedDecision,
  TraceEvent,
  TraceFile,
  TraceToolCallEvent,
  TrustState
} from "./types";

export interface ReplayResult {
  file: string;
  passed: boolean;
  failures: string[];
  originalPolicyHash?: string;
  currentPolicyHash: string;
}

export async function replayPath(
  tracePathOrDir: string,
  configPath?: string
): Promise<ReplayResult[]> {
  const files = await listTraceFiles(path.resolve(tracePathOrDir));
  const loaded = await loadConfig(configPath);
  const results: ReplayResult[] = [];

  for (const file of files) {
    const trace = await readTraceFile(file);
    results.push(await replayTrace(trace, file, loaded.config));
  }

  return results;
}

export async function replayTrace(
  trace: TraceFile,
  file: string,
  config?: Awaited<ReturnType<typeof loadConfig>>["config"]
): Promise<ReplayResult> {
  const activeConfig = config ?? (await loadConfig()).config;
  const currentPolicyHash = hashCanonicalValue(activeConfig.policy);
  let trust: TrustState = createTrustState();
  const failures: string[] = [];

  for (const event of trace.events) {
    if (!isToolCallEvent(event)) continue;
    const trustBefore = cloneTrustState(event.trust.before ?? trust);
    const decision = await evaluatePolicy({
      tool: event.tool,
      risk: event.risk,
      trust: trustBefore,
      config: activeConfig,
      nonInteractive: true
    });
    const expectedDecision = resolveExpectedDecision(event);
    const currentDecision = decision.allowed ? "allowed" : "blocked";

    if (currentDecision !== expectedDecision) {
      failures.push(
        `${event.tool} expected ${expectedDecision} but current policy would be ${currentDecision} (${decision.reason})`
      );
    }

    trust = cloneTrustState(event.trust.after);
  }

  return {
    file,
    passed: failures.length === 0,
    failures,
    originalPolicyHash: trace.policy_hash,
    currentPolicyHash
  };
}

async function listTraceFiles(tracePathOrDir: string): Promise<string[]> {
  const metadata = await stat(tracePathOrDir);
  if (metadata.isFile()) return [tracePathOrDir];

  const entries = await readdir(tracePathOrDir);
  return entries
    .filter((entry) => entry.endsWith(".json"))
    .sort()
    .map((entry) => path.join(tracePathOrDir, entry));
}

export function renderReplayResults(results: ReplayResult[]): string {
  const lines = results.flatMap((result) => {
    const status = result.passed ? "PASS" : "FAIL";
    const detail = result.failures.length > 0 ? ` - ${result.failures.join("; ")}` : "";
    const rendered = [`${status} ${result.file}${detail}`];
    if (result.originalPolicyHash) {
      rendered.push(
        `Policy original=${result.originalPolicyHash} current=${result.currentPolicyHash} changed=${
          result.originalPolicyHash === result.currentPolicyHash ? "no" : "yes"
        }`
      );
    }
    return rendered;
  });
  const failed = results.filter((result) => !result.passed).length;
  lines.push(
    failed === 0
      ? `PASS ${results.length} trace file${results.length === 1 ? "" : "s"}`
      : `FAIL ${failed}/${results.length} trace file${failed === 1 ? "" : "s"}`
  );
  return lines.join("\n");
}

function isToolCallEvent(event: TraceEvent): event is TraceToolCallEvent {
  return event.type === undefined || event.type === "tool_call";
}

function resolveExpectedDecision(event: TraceToolCallEvent): ExpectedDecision {
  return event.expected_decision ?? (event.decision.allowed ? "allowed" : "blocked");
}
