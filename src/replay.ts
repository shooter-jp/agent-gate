import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import { severityAtLeast } from "./classifier";
import { loadConfig } from "./config";
import { evaluatePolicy } from "./policy";
import { readTraceFile } from "./trace";
import { cloneTrustState, createTrustState } from "./trust";
import type { TraceFile, TrustState } from "./types";

export interface ReplayResult {
  file: string;
  passed: boolean;
  failures: string[];
}

export async function replayPath(tracePathOrDir: string, configPath?: string): Promise<ReplayResult[]> {
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
  let trust: TrustState = createTrustState();
  const failures: string[] = [];

  for (const event of trace.events) {
    const trustBefore = cloneTrustState(event.trust.before ?? trust);
    const decision = await evaluatePolicy({
      tool: event.tool,
      risk: event.risk,
      trust: trustBefore,
      config: activeConfig,
      nonInteractive: true
    });

    if (trustBefore.tainted && severityAtLeast(event.risk.severity, "high") && decision.allowed) {
      failures.push(
        `${event.tool} would be allowed while session is tainted (${event.risk.severity})`
      );
    }

    trust = cloneTrustState(event.trust.after);
  }

  return {
    file,
    passed: failures.length === 0,
    failures
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
  const lines = results.map((result) => {
    const status = result.passed ? "PASS" : "FAIL";
    const detail =
      result.failures.length > 0 ? ` - ${result.failures.join("; ")}` : "";
    return `${status} ${result.file}${detail}`;
  });
  const failed = results.filter((result) => !result.passed).length;
  lines.push(
    failed === 0
      ? `PASS ${results.length} trace file${results.length === 1 ? "" : "s"}`
      : `FAIL ${failed}/${results.length} trace file${failed === 1 ? "" : "s"}`
  );
  return lines.join("\n");
}
