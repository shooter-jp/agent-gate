import { spawnSync } from "node:child_process";
import { loadConfig } from "./config";

export async function runDoctor(configPath?: string): Promise<{ ok: boolean; output: string }> {
  const lines: string[] = [];
  const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  const nodeOk = nodeMajor >= 20;
  lines.push(`${nodeOk ? "OK" : "FAIL"} Node.js ${process.versions.node}`);

  const pnpm = spawnSync("pnpm", ["--version"], { encoding: "utf8" });
  const pnpmOk = pnpm.status === 0;
  lines.push(`${pnpmOk ? "OK" : "FAIL"} pnpm ${pnpm.stdout.trim() || "not found"}`);

  let configOk = true;
  try {
    const loaded = await loadConfig(configPath);
    lines.push(`OK config project=${loaded.config.project}`);
    lines.push(`OK trace_dir ${loaded.config.trace_dir}`);
  } catch (error) {
    configOk = false;
    lines.push(`FAIL config ${(error as Error).message}`);
  }

  return {
    ok: nodeOk && pnpmOk && configOk,
    output: lines.join("\n")
  };
}
