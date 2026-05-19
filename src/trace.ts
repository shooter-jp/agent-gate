import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { hashCanonicalValue, redactValue } from "./redaction";
import type { ToolDefinition, ToolRisk, TraceEvent, TraceFile } from "./types";
import { AGENTGATE_VERSION } from "./version";

export interface TraceWriterOptions {
  project: string;
  traceDir: string;
  server?: string;
  policyHash?: string;
  inventory?: Array<ToolDefinition & { risk: ToolRisk; schema_hash?: string }>;
}

export class TraceWriter {
  readonly filePath: string;
  readonly trace: TraceFile;

  private constructor(filePath: string, trace: TraceFile) {
    this.filePath = filePath;
    this.trace = trace;
  }

  static async create(options: TraceWriterOptions): Promise<TraceWriter> {
    await mkdir(options.traceDir, { recursive: true });
    const traceId = `ag_${new Date().toISOString().replace(/[-:.TZ]/g, "")}_${randomUUID().slice(0, 8)}`;
    const trace: TraceFile = {
      trace_id: traceId,
      schema_version: "1.0",
      project: options.project,
      agentgate_version: AGENTGATE_VERSION,
      policy_hash: options.policyHash,
      server: options.server,
      started_at: new Date().toISOString(),
      ended_at: null,
      inventory: options.inventory,
      inventory_complete: options.inventory ? true : undefined,
      tool_inventory_hash: options.inventory ? hashCanonicalValue(options.inventory) : undefined,
      events: []
    };
    const writer = new TraceWriter(path.join(options.traceDir, `${traceId}.json`), trace);
    await writer.flush();
    return writer;
  }

  async setInventory(
    inventory: Array<ToolDefinition & { risk: ToolRisk; schema_hash?: string }>,
    options: { complete?: boolean; nextCursor?: string } = {}
  ): Promise<void> {
    this.trace.inventory = inventory;
    this.trace.inventory_complete = options.complete ?? true;
    if (options.nextCursor) {
      this.trace.inventory_next_cursor = options.nextCursor;
    } else {
      delete this.trace.inventory_next_cursor;
    }
    this.trace.tool_inventory_hash = hashCanonicalValue({
      inventory,
      inventory_complete: this.trace.inventory_complete,
      inventory_next_cursor: this.trace.inventory_next_cursor
    });
    await this.flush();
  }

  async recordInventoryChange(
    reason: "tools/list" | "tools/list_changed",
    options: { complete: boolean; nextCursor?: string }
  ): Promise<void> {
    this.trace.inventory_complete = options.complete;
    if (options.nextCursor) {
      this.trace.inventory_next_cursor = options.nextCursor;
    } else {
      delete this.trace.inventory_next_cursor;
    }
    this.trace.events.push({
      type: "inventory_changed",
      reason,
      at: new Date().toISOString(),
      inventory_complete: options.complete,
      nextCursor: options.nextCursor
    });
    await this.flush();
  }

  async setMcpProtocolVersion(protocolVersion: string): Promise<void> {
    this.trace.mcp_protocol_version = protocolVersion;
    await this.flush();
  }

  async record(event: TraceEvent): Promise<void> {
    if (event.type === "inventory_changed") {
      this.trace.events.push(event);
      await this.flush();
      return;
    }
    this.trace.events.push({
      ...event,
      type: event.type ?? "tool_call",
      arguments: redactValue(event.arguments)
    });
    await this.flush();
  }

  async finalize(): Promise<void> {
    this.trace.ended_at = new Date().toISOString();
    await this.flush();
  }

  async flush(): Promise<void> {
    await writeFile(this.filePath, `${JSON.stringify(this.trace, null, 2)}\n`, "utf8");
  }
}

export async function readTraceFile(filePath: string): Promise<TraceFile> {
  return JSON.parse(await readFile(filePath, "utf8")) as TraceFile;
}
