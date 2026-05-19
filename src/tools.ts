import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { classifyTool } from "./classifier";
import { fileExists, loadConfig, resolveRelative } from "./config";
import type { ToolDefinition, ToolRisk } from "./types";

export interface ClassifiedTool extends ToolDefinition {
  risk: ToolRisk;
}

export function extractTools(value: unknown): ToolDefinition[] {
  const maybeRecord = value as Record<string, unknown>;
  const tools =
    Array.isArray(value)
      ? value
      : Array.isArray(maybeRecord?.tools)
        ? maybeRecord.tools
        : Array.isArray((maybeRecord?.result as Record<string, unknown> | undefined)?.tools)
          ? ((maybeRecord.result as Record<string, unknown>).tools as unknown[])
          : [];

  return tools
    .filter((tool): tool is Record<string, unknown> => Boolean(tool) && typeof tool === "object")
    .filter((tool) => typeof tool.name === "string")
    .map((tool) => ({
      name: tool.name as string,
      description: typeof tool.description === "string" ? tool.description : undefined,
      inputSchema: tool.inputSchema
    }));
}

export function classifyTools(tools: ToolDefinition[]): ClassifiedTool[] {
  return tools.map((tool) => ({ ...tool, risk: classifyTool(tool) }));
}

export async function loadToolsFromPath(
  inputPath: string | undefined,
  cwd = process.cwd()
): Promise<{ tools: ClassifiedTool[]; source: string }> {
  const resolvedPath = inputPath ? path.resolve(cwd, inputPath) : path.resolve(cwd, "agentgate.yml");
  const text = await readFile(resolvedPath, "utf8");
  const extension = path.extname(resolvedPath).toLowerCase();

  if (extension === ".yml" || extension === ".yaml") {
    const raw = parseYaml(text) as Record<string, unknown>;
    const loaded = await loadConfig(resolvedPath, cwd);
    const directTools = extractTools(raw);
    if (directTools.length > 0) {
      return { tools: classifyTools(directTools), source: resolvedPath };
    }
    if (!loaded.config.tools_fixture) {
      return { tools: [], source: resolvedPath };
    }
    const configRelativeFixturePath = resolveRelative(loaded.baseDir, loaded.config.tools_fixture);
    const fixturePath = (await fileExists(configRelativeFixturePath))
      ? configRelativeFixturePath
      : path.resolve(cwd, loaded.config.tools_fixture);
    return loadToolsFromPath(fixturePath, cwd);
  }

  const raw = JSON.parse(text);
  return { tools: classifyTools(extractTools(raw)), source: resolvedPath };
}

export function renderToolTable(tools: ClassifiedTool[]): string {
  const rows = [
    ["Tool", "Action", "Severity", "Matched"],
    ...tools.map((tool) => [
      tool.name,
      tool.risk.action,
      tool.risk.severity,
      tool.risk.matched_keywords.join(", ") || "-"
    ])
  ];
  const widths = rows[0].map((_, column) =>
    Math.max(...rows.map((row) => String(row[column]).length))
  );
  return rows
    .map((row) =>
      row.map((cell, index) => String(cell).padEnd(widths[index])).join("  ").trimEnd()
    )
    .join("\n");
}
