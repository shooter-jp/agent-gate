import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import readline from "node:readline";
import { classifyTool } from "./classifier";
import { loadConfig, resolveRelative } from "./config";
import { evaluatePolicy } from "./policy";
import { hashCanonicalValue, hashPolicyConfig, hashResult } from "./redaction";
import { TraceWriter } from "./trace";
import { createTrustState, updateTrustFromResult } from "./trust";
import type { AgentGateConfig, LoadedConfig, ToolDefinition, ToolRisk, TrustState } from "./types";

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
}

interface PendingRequest {
  resolve: (message: JsonRpcMessage) => void;
}

type InventoryTool = ToolDefinition & { risk: ToolRisk; schema_hash?: string };

export interface JsonRpcProxyIO {
  clientInput?: NodeJS.ReadableStream;
  clientOutput?: NodeJS.WritableStream;
  errorOutput?: NodeJS.WritableStream;
  exit?: (code: number) => void;
}

export interface ProxyOptions {
  configPath: string;
  server?: string;
}

export async function runProxy(options: ProxyOptions): Promise<void> {
  const loaded = await loadConfig(options.configPath);
  const serverName = options.server ?? Object.keys(loaded.config.servers)[0];
  if (!serverName) throw new Error("No server configured");
  const server = loaded.config.servers[serverName];
  if (!server) throw new Error(`Server not found in config: ${serverName}`);

  const upstream = spawn(server.command, server.args, {
    cwd: server.cwd ? resolveRelative(loaded.baseDir, server.cwd) : process.cwd(),
    env: { ...process.env, ...server.env },
    stdio: ["pipe", "pipe", "pipe"]
  });

  const proxy = new JsonRpcProxy(upstream, loaded, serverName);
  await proxy.start();
}

export class JsonRpcProxy {
  private readonly pending = new Map<string | number | null, PendingRequest>();
  private readonly toolRisk = new Map<string, ToolRisk>();
  private readonly toolSchemas = new Map<string, unknown>();
  private readonly inventory = new Map<string, InventoryTool>();
  private readonly clientInput: NodeJS.ReadableStream;
  private readonly clientOutput: NodeJS.WritableStream;
  private readonly errorOutput: NodeJS.WritableStream;
  private readonly exit: (code: number) => void;
  private clientWork: Promise<void> = Promise.resolve();
  private inventoryComplete = false;
  private trust: TrustState = createTrustState();
  private writer?: TraceWriter;

  constructor(
    private readonly upstream: ChildProcessWithoutNullStreams,
    private readonly loaded: LoadedConfig,
    private readonly serverName: string,
    io: JsonRpcProxyIO = {}
  ) {
    this.clientInput = io.clientInput ?? process.stdin;
    this.clientOutput = io.clientOutput ?? process.stdout;
    this.errorOutput = io.errorOutput ?? process.stderr;
    this.exit = io.exit ?? ((code) => process.exit(code));
  }

  async start(): Promise<void> {
    const traceDir = resolveRelative(this.loaded.baseDir, this.loaded.config.trace_dir);
    this.writer = await TraceWriter.create({
      project: this.loaded.config.project,
      traceDir,
      server: this.serverName,
      policyHash: hashPolicyConfig(this.loaded.config)
    });

    this.upstream.stderr.on("data", (chunk) => {
      this.errorOutput.write(chunk);
    });
    this.upstream.on("exit", async () => {
      await this.writer?.finalize();
      this.exit(0);
    });

    readline.createInterface({ input: this.upstream.stdout }).on("line", (line) => {
      this.handleUpstreamLine(line);
    });

    const clientReader = readline.createInterface({ input: this.clientInput });
    clientReader.on("line", (line) => {
      this.clientWork = this.clientWork
        .then(() => this.handleClientLine(line))
        .catch((error) => {
          this.errorOutput.write(`AgentGate proxy error: ${(error as Error).message}\n`);
        });
    });

    await new Promise<void>((resolve) => clientReader.on("close", resolve));
    await this.clientWork;
    await this.writer?.finalize();
    this.upstream.kill();
  }

  private handleUpstreamLine(line: string): void {
    if (!line.trim()) return;
    const message = JSON.parse(line) as JsonRpcMessage;
    if (message.method === "notifications/tools/list_changed") {
      void this.handleToolsListChanged().catch((error) => {
        this.errorOutput.write(`AgentGate proxy error: ${(error as Error).message}\n`);
      });
    }
    if (message.id !== undefined && this.pending.has(message.id)) {
      const pending = this.pending.get(message.id);
      this.pending.delete(message.id);
      pending?.resolve(message);
      return;
    }
    this.clientOutput.write(`${JSON.stringify(message)}\n`);
  }

  private async handleClientLine(line: string): Promise<void> {
    if (!line.trim()) return;
    const request = JSON.parse(line) as JsonRpcMessage;

    if (request.method === "tools/list") {
      const response = await this.forward(request);
      if (response) {
        await this.cacheInventory(request, response);
        this.writeClient(response);
      }
      return;
    }

    if (request.method === "tools/call") {
      await this.handleToolCall(request);
      return;
    }

    const response = await this.forward(request);
    if (response && request.method === "initialize") {
      await this.cacheProtocolVersion(response);
    }
    this.writeClient(response);
  }

  private async cacheInventory(request: JsonRpcMessage, response: JsonRpcMessage): Promise<void> {
    const cursor = extractCursor(request.params);
    if (!cursor) {
      this.toolRisk.clear();
      this.toolSchemas.clear();
      this.inventory.clear();
    }

    const tools = extractToolsFromListResult(response.result);
    for (const tool of tools) {
      const risk = classifyTool(tool);
      const schema_hash = tool.inputSchema ? hashCanonicalValue(tool.inputSchema) : undefined;
      this.toolRisk.set(tool.name, risk);
      if (tool.inputSchema !== undefined) {
        this.toolSchemas.set(tool.name, tool.inputSchema);
      }
      this.inventory.set(tool.name, { ...tool, risk, schema_hash });
    }

    const nextCursor = extractNextCursor(response.result);
    this.inventoryComplete = !nextCursor;
    await this.writer?.setInventory([...this.inventory.values()].sort(compareInventoryTools), {
      complete: this.inventoryComplete,
      nextCursor
    });
  }

  private async handleToolsListChanged(): Promise<void> {
    this.toolRisk.clear();
    this.toolSchemas.clear();
    this.inventory.clear();
    this.inventoryComplete = false;
    await this.writer?.setInventory([], { complete: false });
    await this.writer?.recordInventoryChange("tools/list_changed", { complete: false });
  }

  private async cacheProtocolVersion(response: JsonRpcMessage): Promise<void> {
    const result = response.result as Record<string, unknown> | undefined;
    if (typeof result?.protocolVersion === "string") {
      await this.writer?.setMcpProtocolVersion(result.protocolVersion);
    }
  }

  private async handleToolCall(request: JsonRpcMessage): Promise<void> {
    const params = request.params ?? {};
    const tool = String(params.name ?? "");
    if (!tool) throw new Error("tools/call missing params.name");
    const args = params.arguments ?? {};
    const risk = this.toolRisk.get(tool) ?? classifyTool(tool);
    const trustBefore = this.trust;
    const tool_schema_hash = this.toolSchemas.has(tool)
      ? hashCanonicalValue(this.toolSchemas.get(tool))
      : undefined;

    if (isNotification(request)) {
      const reason =
        "tools/call notifications are blocked because their results cannot be audited";
      await this.writer?.record({
        type: "tool_call",
        request_kind: "notification",
        tool,
        arguments: args,
        risk,
        trust: { before: trustBefore, after: trustBefore },
        decision: {
          policy_action: "block",
          allowed: false,
          reason
        },
        reason,
        evidence: trustBefore.sources.map((source) => source.evidence).join(" | "),
        result_hash: null,
        tool_schema_hash,
        expected_decision: "blocked"
      });
      return;
    }

    const decision = await evaluatePolicy({
      tool,
      risk,
      trust: trustBefore,
      config: this.loaded.config,
      nonInteractive: true
    });

    if (!decision.allowed) {
      await this.writer?.record({
        type: "tool_call",
        tool,
        arguments: args,
        risk,
        trust: { before: trustBefore, after: trustBefore },
        decision,
        reason: decision.reason,
        evidence: trustBefore.sources.map((source) => source.evidence).join(" | "),
        result_hash: null,
        tool_schema_hash,
        expected_decision: "blocked"
      });
      if (!isNotification(request)) {
        this.writeClient(blockedToolResult(request, tool, decision.reason));
      }
      return;
    }

    const response = await this.forward(request);
    if (!response) return;
    const trustUpdate = updateTrustFromResult(
      this.trust,
      tool,
      response.result,
      this.loaded.config.untrusted_tools
    );
    this.trust = trustUpdate.after;
    await this.writer?.record({
      type: "tool_call",
      tool,
      arguments: args,
      risk,
      trust: { before: trustUpdate.before, after: trustUpdate.after },
      decision,
      reason: decision.reason,
      evidence: trustUpdate.evidence.map((item) => item.evidence).join(" | "),
      result_hash: hashResult(response.result),
      tool_schema_hash,
      expected_decision: "allowed"
    });
    this.writeClient(response);
  }

  private forward(request: JsonRpcMessage): Promise<JsonRpcMessage | undefined> {
    const id = request.id;
    if (id === undefined) {
      this.upstream.stdin.write(`${JSON.stringify(request)}\n`);
      return Promise.resolve(undefined);
    }

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve });
      this.upstream.stdin.write(`${JSON.stringify(request)}\n`);
      this.upstream.once("error", reject);
    });
  }

  private writeClient(message: JsonRpcMessage | undefined): void {
    if (!message) return;
    this.clientOutput.write(`${JSON.stringify(message)}\n`);
  }
}

function blockedToolResult(request: JsonRpcMessage, tool: string, reason: string): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id: request.id,
    result: {
      content: [
        {
          type: "text",
          text: `AgentGate blocked ${tool}: ${reason}`
        }
      ],
      isError: true
    }
  };
}

function extractToolsFromListResult(result: unknown): ToolDefinition[] {
  const maybeRecord = result as Record<string, unknown>;
  const tools = Array.isArray(maybeRecord?.tools) ? maybeRecord.tools : [];
  return tools
    .filter((tool): tool is Record<string, unknown> => Boolean(tool) && typeof tool === "object")
    .filter((tool) => typeof tool.name === "string")
    .map((tool) => ({
      name: tool.name as string,
      description: typeof tool.description === "string" ? tool.description : undefined,
      inputSchema: tool.inputSchema
    }));
}

function extractCursor(params: unknown): string | undefined {
  const maybeRecord = params as Record<string, unknown> | undefined;
  return typeof maybeRecord?.cursor === "string" ? maybeRecord.cursor : undefined;
}

function extractNextCursor(result: unknown): string | undefined {
  const maybeRecord = result as Record<string, unknown> | undefined;
  return typeof maybeRecord?.nextCursor === "string" ? maybeRecord.nextCursor : undefined;
}

function isNotification(message: JsonRpcMessage): boolean {
  return message.id === undefined;
}

function compareInventoryTools(a: InventoryTool, b: InventoryTool): number {
  return a.name.localeCompare(b.name);
}

export function proxyConfigSummary(config: AgentGateConfig): string {
  return Object.keys(config.servers).join(", ");
}
