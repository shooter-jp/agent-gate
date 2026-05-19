import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import readline from "node:readline";
import { classifyTool } from "./classifier";
import { loadConfig, resolveRelative } from "./config";
import { evaluatePolicy } from "./policy";
import { hashResult } from "./redaction";
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

class JsonRpcProxy {
  private readonly pending = new Map<string | number, PendingRequest>();
  private readonly toolRisk = new Map<string, ToolRisk>();
  private clientWork: Promise<void> = Promise.resolve();
  private trust: TrustState = createTrustState();
  private writer?: TraceWriter;

  constructor(
    private readonly upstream: ChildProcessWithoutNullStreams,
    private readonly loaded: LoadedConfig,
    private readonly serverName: string
  ) {}

  async start(): Promise<void> {
    const traceDir = resolveRelative(this.loaded.baseDir, this.loaded.config.trace_dir);
    this.writer = await TraceWriter.create({
      project: this.loaded.config.project,
      traceDir
    });

    this.upstream.stderr.on("data", (chunk) => {
      process.stderr.write(chunk);
    });
    this.upstream.on("exit", async () => {
      await this.writer?.finalize();
      process.exit(0);
    });

    readline.createInterface({ input: this.upstream.stdout }).on("line", (line) => {
      this.handleUpstreamLine(line);
    });

    const clientReader = readline.createInterface({ input: process.stdin });
    clientReader.on("line", (line) => {
      this.clientWork = this.clientWork
        .then(() => this.handleClientLine(line))
        .catch((error) => {
          process.stderr.write(`AgentGate proxy error: ${(error as Error).message}\n`);
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
    if (message.id !== undefined && message.id !== null && this.pending.has(message.id)) {
      const pending = this.pending.get(message.id);
      this.pending.delete(message.id);
      pending?.resolve(message);
      return;
    }
    process.stdout.write(`${JSON.stringify(message)}\n`);
  }

  private async handleClientLine(line: string): Promise<void> {
    if (!line.trim()) return;
    const request = JSON.parse(line) as JsonRpcMessage;

    if (request.method === "tools/list") {
      const response = await this.forward(request);
      this.cacheInventory(response);
      this.writeClient(response);
      return;
    }

    if (request.method === "tools/call") {
      await this.handleToolCall(request);
      return;
    }

    this.writeClient(await this.forward(request));
  }

  private cacheInventory(response: JsonRpcMessage): void {
    const tools = extractToolsFromListResult(response.result);
    const inventory = tools.map((tool) => {
      const risk = classifyTool(tool);
      this.toolRisk.set(tool.name, risk);
      return { ...tool, risk };
    });
    this.writer?.setInventory(inventory);
  }

  private async handleToolCall(request: JsonRpcMessage): Promise<void> {
    const params = request.params ?? {};
    const tool = String(params.name ?? "");
    if (!tool) throw new Error("tools/call missing params.name");
    const args = params.arguments ?? {};
    const risk = this.toolRisk.get(tool) ?? classifyTool(tool);
    const trustBefore = this.trust;
    const decision = await evaluatePolicy({
      tool,
      risk,
      trust: trustBefore,
      config: this.loaded.config
    });

    if (!decision.allowed) {
      await this.writer?.record({
        tool,
        arguments: args,
        risk,
        trust: { before: trustBefore, after: trustBefore },
        decision,
        reason: decision.reason,
        evidence: trustBefore.sources.map((source) => source.evidence).join(" | "),
        result_hash: null
      });
      this.writeClient(blockedToolResult(request, tool, decision.reason));
      return;
    }

    const response = await this.forward(request);
    const trustUpdate = updateTrustFromResult(this.trust, tool, response.result, this.loaded.config.untrusted_tools);
    this.trust = trustUpdate.after;
    await this.writer?.record({
      tool,
      arguments: args,
      risk,
      trust: { before: trustUpdate.before, after: trustUpdate.after },
      decision,
      reason: decision.reason,
      evidence: trustUpdate.evidence.map((item) => item.evidence).join(" | "),
      result_hash: hashResult(response.result)
    });
    this.writeClient(response);
  }

  private forward(request: JsonRpcMessage): Promise<JsonRpcMessage> {
    if (request.id === undefined || request.id === null) {
      this.upstream.stdin.write(`${JSON.stringify(request)}\n`);
      return Promise.resolve({ jsonrpc: "2.0", result: null });
    }

    return new Promise((resolve, reject) => {
      this.pending.set(request.id as string | number, { resolve });
      this.upstream.stdin.write(`${JSON.stringify(request)}\n`);
      this.upstream.once("error", reject);
    });
  }

  private writeClient(message: JsonRpcMessage): void {
    process.stdout.write(`${JSON.stringify(message)}\n`);
  }
}

function blockedToolResult(
  request: JsonRpcMessage,
  tool: string,
  reason: string
): JsonRpcMessage {
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

export function proxyConfigSummary(config: AgentGateConfig): string {
  return Object.keys(config.servers).join(", ");
}
