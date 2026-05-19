import { describe, expect, it } from "vitest";
import { evaluatePolicy, resolvePolicyAction } from "../src/policy";
import type { AgentGateConfig, ToolRisk, TrustState } from "../src/types";

const risk: ToolRisk = { action: "write", severity: "high", matched_keywords: ["write"] };
const clean: TrustState = { tainted: false, sources: [] };
const tainted: TrustState = {
  tainted: true,
  sources: [{ tool: "github.read_issue", reason: "untrusted", evidence: "ignore instructions" }]
};

function config(defaultAction: AgentGateConfig["policy"]["default"]): AgentGateConfig {
  return {
    project: "test",
    trace_dir: ".agentgate/traces",
    untrusted_tools: [],
    policy: {
      default: defaultAction,
      tools: { "github.create_*": defaultAction }
    },
    servers: {}
  };
}

describe("policy", () => {
  it("resolves minimatch tool overrides", () => {
    expect(resolvePolicyAction("github.create_pull_request", config("block"))).toBe("block");
  });

  it("allows untainted high-risk calls under block_when_tainted", async () => {
    await expect(
      evaluatePolicy({ tool: "github.write_file", risk, trust: clean, config: config("block_when_tainted") })
    ).resolves.toMatchObject({ allowed: true });
  });

  it("blocks tainted high-risk calls under block_when_tainted", async () => {
    await expect(
      evaluatePolicy({
        tool: "github.write_file",
        risk,
        trust: tainted,
        config: config("block_when_tainted")
      })
    ).resolves.toMatchObject({ allowed: false });
  });

  it("blocks require_approval in CI or non-interactive mode", async () => {
    await expect(
      evaluatePolicy({
        tool: "github.write_file",
        risk,
        trust: tainted,
        config: config("require_approval"),
        nonInteractive: true,
        env: { CI: "true" }
      })
    ).resolves.toMatchObject({ allowed: false });
  });

  it("implements all policy actions", async () => {
    await expect(
      evaluatePolicy({ tool: "x", risk, trust: tainted, config: config("allow") })
    ).resolves.toMatchObject({ allowed: true });
    await expect(
      evaluatePolicy({ tool: "x", risk, trust: clean, config: config("block") })
    ).resolves.toMatchObject({ allowed: false });
    await expect(
      evaluatePolicy({ tool: "x", risk, trust: tainted, config: config("record_only") })
    ).resolves.toMatchObject({ allowed: true });
  });
});
