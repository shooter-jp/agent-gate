import { access, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { z } from "zod";
import { policyActions, severityOrder, type AgentGateConfig, type LoadedConfig } from "./types";

const PolicyActionSchema = z.enum(policyActions);
const RiskSeveritySchema = z.enum(severityOrder);

const ServerConfigSchema = z.object({
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  env: z.record(z.string(), z.string()).optional()
});

const RawConfigSchema = z.object({
  project: z.string().min(1).optional(),
  trace_dir: z.string().min(1).optional(),
  untrusted_tools: z.array(z.string()).optional(),
  policy: z
    .object({
      default: PolicyActionSchema.optional(),
      tainted_block_threshold: RiskSeveritySchema.optional(),
      tools: z.record(z.string(), PolicyActionSchema).optional()
    })
    .optional(),
  servers: z.record(z.string(), ServerConfigSchema).optional(),
  tools_fixture: z.string().optional()
});

export const defaultConfig: AgentGateConfig = {
  project: "agentgate",
  trace_dir: ".agentgate/traces",
  untrusted_tools: [],
  policy: {
    default: "block_when_tainted",
    tainted_block_threshold: "medium",
    tools: {}
  },
  servers: {},
  tools_fixture: undefined
};

export const exampleConfig: AgentGateConfig = {
  project: "agentgate-example",
  trace_dir: ".agentgate/traces",
  untrusted_tools: ["github.read_*"],
  policy: {
    default: "block_when_tainted",
    tainted_block_threshold: "medium",
    tools: {
      "github.create_*": "block_when_tainted",
      "github.write_*": "block_when_tainted"
    }
  },
  servers: {
    github: {
      command: "node",
      args: ["examples/mock-github-server.mjs"]
    }
  },
  tools_fixture: "examples/tools/github-tools.json"
};

export function normalizeConfig(
  raw: unknown,
  fallbackProject = defaultConfig.project
): AgentGateConfig {
  const parsed = RawConfigSchema.parse(raw ?? {});
  return {
    project: parsed.project ?? fallbackProject,
    trace_dir: parsed.trace_dir ?? defaultConfig.trace_dir,
    untrusted_tools: parsed.untrusted_tools ?? [],
    policy: {
      default: parsed.policy?.default ?? defaultConfig.policy.default,
      tainted_block_threshold:
        parsed.policy?.tainted_block_threshold ?? defaultConfig.policy.tainted_block_threshold,
      tools: parsed.policy?.tools ?? {}
    },
    servers: parsed.servers ?? {},
    tools_fixture: parsed.tools_fixture
  };
}

export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function findConfigPath(cwd = process.cwd()): Promise<string | undefined> {
  const candidates = ["agentgate.yml", "agentgate.yaml"];
  for (const candidate of candidates) {
    const fullPath = path.resolve(cwd, candidate);
    if (await fileExists(fullPath)) return fullPath;
  }
  return undefined;
}

export async function loadConfig(configPath?: string, cwd = process.cwd()): Promise<LoadedConfig> {
  const resolvedPath = configPath ? path.resolve(cwd, configPath) : await findConfigPath(cwd);
  if (!resolvedPath) {
    return {
      config: normalizeConfig({}, path.basename(cwd)),
      baseDir: cwd
    };
  }

  const rawText = await readFile(resolvedPath, "utf8");
  const raw = parseYaml(rawText);
  return {
    config: normalizeConfig(raw, path.basename(path.dirname(resolvedPath))),
    path: resolvedPath,
    baseDir: path.dirname(resolvedPath)
  };
}

export function resolveRelative(baseDir: string, maybeRelativePath: string): string {
  return path.isAbsolute(maybeRelativePath)
    ? maybeRelativePath
    : path.resolve(baseDir, maybeRelativePath);
}

export function configToYaml(config: AgentGateConfig = exampleConfig): string {
  return stringifyYaml(config);
}

export async function writeDefaultConfig(targetPath: string): Promise<void> {
  await writeFile(targetPath, configToYaml(exampleConfig), "utf8");
}
