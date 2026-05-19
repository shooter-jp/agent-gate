import { type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { JsonRpcProxy } from "../src/proxy";
import { hashPolicyConfig } from "../src/redaction";
import type { AgentGateConfig, LoadedConfig, TraceFile } from "../src/types";

const tempDirs: string[] = [];

interface FakeUpstream extends ChildProcessWithoutNullStreams {
  stdin: PassThrough;
  stdout: PassThrough;
  stderr: PassThrough;
  kill: ChildProcessWithoutNullStreams["kill"];
}

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "agentgate-proxy-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("JsonRpcProxy", () => {
  it("forwards notifications/initialized without writing a response", async () => {
    const harness = await startHarness();
    harness.clientInput.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`
    );

    expect(JSON.parse(await harness.upstreamInput.nextLine())).toMatchObject({
      method: "notifications/initialized"
    });
    await waitForSettled();
    expect(harness.clientOutput.lines()).toEqual([]);

    await harness.close();
  });

  it("forwards generic no-id notifications without writing a response", async () => {
    const harness = await startHarness();
    harness.clientInput.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } })}\n`
    );

    expect(JSON.parse(await harness.upstreamInput.nextLine())).toMatchObject({
      method: "notifications/cancelled"
    });
    await waitForSettled();
    expect(harness.clientOutput.lines()).toEqual([]);

    await harness.close();
  });

  it("blocks tools/call notifications without forwarding or responding", async () => {
    const harness = await startHarness();
    harness.clientInput.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        params: { name: "github.read_issue", arguments: { issue_number: 1 } }
      })}\n`
    );

    await waitForTraceEvent(harness.traceDir, "tool_call");
    await waitForSettled();
    expect(harness.upstreamInput.lines()).toEqual([]);
    expect(harness.clientOutput.lines()).toEqual([]);

    const trace = await readOnlyTrace(harness.traceDir);
    expect(trace.events[0]).toMatchObject({
      type: "tool_call",
      request_kind: "notification",
      tool: "github.read_issue",
      decision: {
        policy_action: "block",
        allowed: false
      },
      result_hash: null,
      expected_decision: "blocked"
    });

    await harness.close();
  });

  it("keeps proxy stdout JSON-RPC-only when approval would be required", async () => {
    const harness = await startHarness({
      policy: { default: "require_approval", tainted_block_threshold: "medium", tools: {} }
    });
    harness.clientInput.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "repo.apply_patch", arguments: { path: "README.md" } }
      })}\n`
    );

    const line = await harness.clientOutput.nextLine();
    expect(() => JSON.parse(line)).not.toThrow();
    expect(line).not.toContain("Approve?");
    expect(line).not.toContain("AgentGate approval required");
    expect(JSON.parse(line)).toMatchObject({
      id: 1,
      result: { isError: true }
    });
    expect(harness.upstreamInput.lines()).toEqual([]);

    await harness.close();
  });

  it("includes untrusted tools in the trace policy hash", async () => {
    const first = await startHarness();
    const second = await startHarness({ untrusted_tools: ["docs.read_*"] });

    const firstTrace = await readOnlyTrace(first.traceDir);
    const secondTrace = await readOnlyTrace(second.traceDir);
    expect(firstTrace.policy_hash).toBe(hashPolicyConfig(first.config));
    expect(secondTrace.policy_hash).toBe(hashPolicyConfig(second.config));
    expect(firstTrace.policy_hash).not.toBe(secondTrace.policy_hash);

    await first.close();
    await second.close();
  });

  it("merges paginated tools/list inventory and invalidates on list_changed", async () => {
    const harness = await startHarness();
    harness.clientInput.write(
      `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })}\n`
    );
    expect(JSON.parse(await harness.upstreamInput.nextLine())).toMatchObject({
      id: 1,
      method: "tools/list"
    });
    harness.upstream.stdout.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          tools: [
            {
              name: "github.read_issue",
              description: "Read a GitHub issue",
              inputSchema: { type: "object" }
            }
          ],
          nextCursor: "page-2"
        }
      })}\n`
    );
    await harness.clientOutput.nextLine();

    let trace = await readOnlyTrace(harness.traceDir);
    expect(trace.inventory_complete).toBe(false);
    expect(trace.inventory_next_cursor).toBe("page-2");
    expect(trace.inventory?.map((tool) => tool.name)).toEqual(["github.read_issue"]);

    harness.clientInput.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: { cursor: "page-2" }
      })}\n`
    );
    expect(JSON.parse(await harness.upstreamInput.nextLine())).toMatchObject({
      id: 2,
      params: { cursor: "page-2" }
    });
    harness.upstream.stdout.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        result: {
          tools: [
            {
              name: "github.create_pull_request",
              description: "Create a pull request",
              inputSchema: { type: "object", properties: { body: { type: "string" } } }
            }
          ]
        }
      })}\n`
    );
    await harness.clientOutput.nextLine();

    trace = await readOnlyTrace(harness.traceDir);
    expect(trace.inventory_complete).toBe(true);
    expect(trace.inventory_next_cursor).toBeUndefined();
    expect(trace.inventory?.map((tool) => tool.name)).toEqual([
      "github.create_pull_request",
      "github.read_issue"
    ]);

    harness.upstream.stdout.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/tools/list_changed" })}\n`
    );
    expect(JSON.parse(await harness.clientOutput.nextLine())).toMatchObject({
      method: "notifications/tools/list_changed"
    });
    await waitForTraceEvent(harness.traceDir, "inventory_changed");

    trace = await readOnlyTrace(harness.traceDir);
    expect(trace.inventory_complete).toBe(false);
    expect(trace.inventory).toEqual([]);
    expect(trace.events).toContainEqual(
      expect.objectContaining({ type: "inventory_changed", reason: "tools/list_changed" })
    );

    await harness.close();
  });
});

async function startHarness(configOverrides: Partial<AgentGateConfig> = {}) {
  const cwd = await tempDir();
  const traceDir = path.join(cwd, "traces");
  const upstream = createFakeUpstream();
  const clientInput = new PassThrough();
  const clientOutputStream = new PassThrough();
  const errorOutput = new PassThrough();
  const clientOutput = lineReader(clientOutputStream);
  const upstreamInput = lineReader(upstream.stdin);
  const baseConfig: AgentGateConfig = {
    project: "proxy-test",
    trace_dir: traceDir,
    untrusted_tools: ["github.read_*"],
    policy: {
      default: "block_when_tainted",
      tainted_block_threshold: "medium",
      tools: {}
    },
    servers: {}
  };
  const config: AgentGateConfig = {
    ...baseConfig,
    ...configOverrides,
    policy: {
      ...baseConfig.policy,
      ...configOverrides.policy,
      tools: configOverrides.policy?.tools ?? baseConfig.policy.tools
    }
  };
  const loaded: LoadedConfig = { config, baseDir: cwd };
  const proxy = new JsonRpcProxy(upstream, loaded, "github", {
    clientInput,
    clientOutput: clientOutputStream,
    errorOutput,
    exit: vi.fn()
  });
  const running = proxy.start();
  await waitForTraceFile(traceDir);

  return {
    cwd,
    traceDir,
    upstream,
    clientInput,
    clientOutput,
    upstreamInput,
    config,
    async close() {
      clientInput.end();
      await running;
    }
  };
}

function createFakeUpstream(): FakeUpstream {
  const upstream = new EventEmitter() as EventEmitter & {
    stdin: PassThrough;
    stdout: PassThrough;
    stderr: PassThrough;
    kill: ChildProcessWithoutNullStreams["kill"];
  };
  upstream.stdin = new PassThrough();
  upstream.stdout = new PassThrough();
  upstream.stderr = new PassThrough();
  upstream.kill = vi.fn(() => true) as unknown as ChildProcessWithoutNullStreams["kill"];
  return upstream as unknown as FakeUpstream;
}

function lineReader(stream: NodeJS.ReadableStream) {
  const lines: string[] = [];
  const waiters: Array<(line: string) => void> = [];
  let buffer = "";
  stream.on("data", (chunk) => {
    buffer += chunk.toString();
    let newline = buffer.indexOf("\n");
    while (newline >= 0) {
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      const waiter = waiters.shift();
      if (waiter) waiter(line);
      else lines.push(line);
      newline = buffer.indexOf("\n");
    }
  });

  return {
    lines: () => [...lines],
    nextLine: (timeoutMs = 1000) =>
      new Promise<string>((resolve, reject) => {
        const existing = lines.shift();
        if (existing !== undefined) {
          resolve(existing);
          return;
        }
        const timeout = setTimeout(
          () => reject(new Error("Timed out waiting for line")),
          timeoutMs
        );
        waiters.push((line) => {
          clearTimeout(timeout);
          resolve(line);
        });
      })
  };
}

async function waitForTraceFile(traceDir: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const files = await readdir(traceDir);
      if (files.some((file) => file.endsWith(".json"))) return;
    } catch {
      // trace directory is created asynchronously by the proxy
    }
    await waitForSettled();
  }
  throw new Error("Timed out waiting for trace file");
}

async function readOnlyTrace(traceDir: string): Promise<TraceFile> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const files = (await readdir(traceDir)).filter((file) => file.endsWith(".json"));
      expect(files).toHaveLength(1);
      const text = await readFile(path.join(traceDir, files[0]), "utf8");
      if (text.trim()) return JSON.parse(text) as TraceFile;
    } catch (error) {
      lastError = error;
    }
    await waitForSettled();
  }
  throw lastError instanceof Error ? lastError : new Error("Timed out reading trace");
}

async function waitForTraceEvent(traceDir: string, eventType: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const trace = await readOnlyTrace(traceDir);
    if (trace.events.some((event) => event.type === eventType)) return;
    await waitForSettled();
  }
  throw new Error(`Timed out waiting for trace event: ${eventType}`);
}

function waitForSettled(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 10));
}
