import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { exampleConfig } from "../src/config";
import { runGithubInjectionDemo } from "../src/demo";
import { renderReplayResults, replayTrace } from "../src/replay";
import { TraceWriter } from "../src/trace";
import type { TraceFile, TraceToolCallEvent } from "../src/types";

const tempDirs: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "agentgate-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function event(overrides: Partial<TraceToolCallEvent> = {}): TraceToolCallEvent {
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
    expect((trace.events[0] as TraceToolCallEvent | undefined)?.arguments).toMatchObject({
      token: "[REDACTED]"
    });
  });

  it("flushes inventory metadata immediately", async () => {
    const dir = await tempDir();
    const writer = await TraceWriter.create({
      project: "test",
      traceDir: dir,
      server: "github",
      policyHash: "sha256:policy"
    });
    await writer.setInventory(
      [
        {
          name: "github.read_issue",
          risk: { action: "read", severity: "low", matched_keywords: ["read"] },
          schema_hash: "sha256:schema"
        }
      ],
      { complete: false, nextCursor: "next-page" }
    );

    const trace = JSON.parse(await readFile(writer.filePath, "utf8")) as TraceFile;
    expect(trace.agentgate_version).toBe("0.1.0");
    expect(trace.server).toBe("github");
    expect(trace.policy_hash).toBe("sha256:policy");
    expect(trace.tool_inventory_hash).toMatch(/^sha256:/);
    expect(trace.inventory_complete).toBe(false);
    expect(trace.inventory_next_cursor).toBe("next-page");
    expect(trace.inventory).toHaveLength(1);
  });
});

describe("replay", () => {
  const cleanTrust = {
    tainted: false,
    sources: []
  };

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
        policy: { default: "allow", tainted_block_threshold: "medium", tools: {} }
      })
    ).resolves.toMatchObject({ passed: false });
  });

  it("fails expected blocked tainted medium-risk regressions", async () => {
    const trace: TraceFile = {
      trace_id: "test",
      schema_version: "1.0",
      project: "test",
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
      events: [
        event({
          risk: { action: "unknown", severity: "medium", matched_keywords: [] },
          expected_decision: "blocked"
        })
      ]
    };
    await expect(
      replayTrace(trace, "trace.json", {
        ...exampleConfig,
        policy: { default: "allow", tainted_block_threshold: "medium", tools: {} }
      })
    ).resolves.toMatchObject({ passed: false });
  });

  it("fails when an explicitly blocked clean call would now be allowed", async () => {
    const trace: TraceFile = {
      trace_id: "test",
      schema_version: "1.0",
      project: "test",
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
      events: [
        event({
          trust: { before: cleanTrust, after: cleanTrust },
          decision: {
            policy_action: "block",
            allowed: false,
            reason: "policy blocked tool call"
          },
          reason: "policy blocked tool call",
          expected_decision: "blocked"
        })
      ]
    };
    const result = await replayTrace(trace, "trace.json", {
      ...exampleConfig,
      policy: { default: "allow", tainted_block_threshold: "medium", tools: {} }
    });

    expect(result.passed).toBe(false);
    expect(result.failures[0]).toContain("expected blocked");
  });

  it("fails when an expected allowed call would now be blocked", async () => {
    const trace: TraceFile = {
      trace_id: "test",
      schema_version: "1.0",
      project: "test",
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
      events: [
        event({
          trust: { before: cleanTrust, after: cleanTrust },
          decision: {
            policy_action: "allow",
            allowed: true,
            reason: "policy allowed tool call"
          },
          reason: "policy allowed tool call",
          result_hash: "sha256:allowed",
          expected_decision: "allowed"
        })
      ]
    };
    const result = await replayTrace(trace, "trace.json", {
      ...exampleConfig,
      policy: { default: "block", tainted_block_threshold: "medium", tools: {} }
    });

    expect(result.passed).toBe(false);
    expect(result.failures[0]).toContain("expected allowed");
  });

  it("skips inventory events and renders policy hash comparisons", async () => {
    const trace: TraceFile = {
      trace_id: "test",
      schema_version: "1.0",
      project: "test",
      policy_hash: "sha256:original",
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
      events: [
        {
          type: "inventory_changed",
          reason: "tools/list_changed",
          at: new Date().toISOString(),
          inventory_complete: false
        },
        event()
      ]
    };
    const result = await replayTrace(trace, "trace.json", exampleConfig);
    expect(result.passed).toBe(true);
    expect(renderReplayResults([result])).toContain("Policy original=sha256:original");
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
    expect((trace.events[1] as TraceToolCallEvent | undefined)?.decision.allowed).toBe(false);
  });
});
