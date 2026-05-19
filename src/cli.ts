#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Command } from "commander";
import { severityAtLeast } from "./classifier";
import { configToYaml, fileExists } from "./config";
import { runGithubInjectionDemo } from "./demo";
import { runDoctor } from "./doctor";
import { runProxy } from "./proxy";
import { renderReplayResults, replayPath } from "./replay";
import { loadToolsFromPath, renderToolTable } from "./tools";

const program = new Command();

program
  .name("agentgate")
  .description("The tool-call firewall for AI agents.")
  .version("0.1.0");

program
  .command("init")
  .description("Create agentgate.yml and the default trace directory.")
  .option("--force", "overwrite existing agentgate.yml")
  .action(async (options: { force?: boolean }) => {
    const configPath = path.resolve(process.cwd(), "agentgate.yml");
    if ((await fileExists(configPath)) && !options.force) {
      throw new Error("agentgate.yml already exists; pass --force to overwrite");
    }

    await writeFile(configPath, configToYaml(), "utf8");
    await mkdir(path.resolve(process.cwd(), ".agentgate/traces"), { recursive: true });
    console.log(`Created ${configPath}`);
    console.log("Created .agentgate/traces");
  });

program
  .command("scan")
  .description("Classify configured or fixture tools.")
  .argument("[configOrToolsPath]", "agentgate.yml or JSON tools fixture")
  .option("--json", "print JSON")
  .option("--fail-on <severity>", "exit non-zero for tools at or above high|critical")
  .action(
    async (
      configOrToolsPath: string | undefined,
      options: { json?: boolean; failOn?: "high" | "critical" }
    ) => {
      const { tools, source } = await loadToolsFromPath(configOrToolsPath);
      if (options.json) {
        console.log(JSON.stringify({ source, tools }, null, 2));
      } else {
        console.log(renderToolTable(tools));
      }

      if (options.failOn && tools.some((tool) => severityAtLeast(tool.risk.severity, options.failOn))) {
        process.exitCode = 1;
      }
    }
  );

program
  .command("proxy")
  .description("Run a minimal STDIO JSON-RPC tool-call firewall proxy.")
  .requiredOption("--config <path>", "agentgate.yml path")
  .option("--server <name>", "server name from config")
  .action(async (options: { config: string; server?: string }) => {
    await runProxy({ configPath: options.config, server: options.server });
  });

program
  .command("replay")
  .description("Re-evaluate trace JSON files against the current policy.")
  .argument("<tracePathOrDir>", "trace JSON file or directory")
  .option("--config <path>", "agentgate.yml path")
  .action(async (tracePathOrDir: string, options: { config?: string }) => {
    const results = await replayPath(tracePathOrDir, options.config);
    console.log(renderReplayResults(results));
    if (results.some((result) => !result.passed)) process.exitCode = 1;
  });

program
  .command("demo")
  .description("Run a credential-free local demo.")
  .argument("<name>", "demo name")
  .action(async (name: string) => {
    if (name !== "github-injection") {
      throw new Error(`Unknown demo: ${name}`);
    }
    const result = await runGithubInjectionDemo();
    console.log(result.output);
  });

program
  .command("doctor")
  .description("Check local AgentGate prerequisites.")
  .option("--config <path>", "agentgate.yml path")
  .action(async (options: { config?: string }) => {
    const result = await runDoctor(options.config);
    console.log(result.output);
    if (!result.ok) process.exitCode = 1;
  });

program.parseAsync().catch((error: unknown) => {
  console.error(`ERROR: ${(error as Error).message}`);
  process.exit(1);
});
