import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { exampleConfig } from "../src/config";
import { runGithubInjectionDemo } from "../src/demo";
import { replayTrace } from "../src/replay";
import { TraceWriter } from "../src/trace";
import type { TraceEvent, TraceFile } from "../src/types";

const tempDirs: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "agentgate-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function event(overrides: Partial<TraceEvent> = {}): TraceEvent {
  return {
    tool: "github.create_pull_request",
    arguments: { title: "demo", token: "sk-abcdefghijklmnopqrstuvwxyz" },
    risk: { action: "write", severity: "high", matched_keywords: ["create"] },
    trust: {
      before: {
        tainted: true,
        sources: [{ tool: "github.read_issue", reason: "untrusted", evidence: "ignore" }]
      },
      after: {
        tainted: true,
        sources: [{ tool: "github.read_issue", reason: "untrusted", evidence: "ignore" }]
      }
    },
    decision: {
      policy_action: "block_when_tainted",
      allowed: false,
      reason: "blocked high-risk tool call because session is tainted"
    },
    reason: "blocked high-risk tool call because session is tainted",
    evidence: "ignore",
    result_hash: null,
    ...overrides
  };
}

describe("trace writer", () => {
  it("writes redacted trace events", async () => {
    const dir = await tempDir();
    const writer = await TraceWriter.create({ project: "test", traceDir: dir });
    await writer.record(event());
    await writer.finalize();
    const trace = JSON.parse(await readFile(writer.filePath, "utf8")) as TraceFile;
    expect(trace.schema_version).toBe("1.0");
    expect(trace.events[0]?.arguments).toMatchObject({ token: "[REDACTED]" });
  });
});

describe("replay", () => {
  it("passes when a tainted dangerous call remains blocked", async () => {
    const trace: TraceFile = {
      trace_id: "test",
      schema_version: "1.0",
      project: "test",
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
      events: [event()]
    };
    await expect(replayTrace(trace, "trace.json", exampleConfig)).resolves.toMatchObject({
      passed: true
    });
  });

  it("fails when current policy would allow a tainted dangerous call", async () => {
    const trace: TraceFile = {
      trace_id: "test",
      schema_version: "1.0",
      project: "test",
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
      events: [event()]
    };
    await expect(
      replayTrace(trace, "trace.json", {
        ...exampleConfig,
        policy: { default: "allow", tools: {} }
      })
    ).resolves.toMatchObject({ passed: false });
  });
});

describe("demo", () => {
  it("blocks the simulated GitHub injection and writes a trace", async () => {
    const dir = await tempDir();
    const result = await runGithubInjectionDemo(dir);
    expect(result.blocked).toBe(true);
    expect(result.output).toContain("BLOCKED");
    const trace = JSON.parse(await readFile(result.tracePath, "utf8")) as TraceFile;
    expect(trace.events).toHaveLength(2);
    expect(trace.events[1]?.decision.allowed).toBe(false);
  });
});
