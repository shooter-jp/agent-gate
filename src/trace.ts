import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { redactValue } from "./redaction";
import type { ToolDefinition, ToolRisk, TraceEvent, TraceFile } from "./types";

export interface TraceWriterOptions {
  project: string;
  traceDir: string;
  inventory?: Array<ToolDefinition & { risk: ToolRisk }>;
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
      started_at: new Date().toISOString(),
      ended_at: null,
      inventory: options.inventory,
      events: []
    };
    const writer = new TraceWriter(path.join(options.traceDir, `${traceId}.json`), trace);
    await writer.flush();
    return writer;
  }

  setInventory(inventory: Array<ToolDefinition & { risk: ToolRisk }>): void {
    this.trace.inventory = inventory;
  }

  async record(event: TraceEvent): Promise<void> {
    this.trace.events.push({
      ...event,
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
