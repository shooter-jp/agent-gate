import { createInterface } from "node:readline/promises";
import { minimatch } from "minimatch";
import { severityAtLeast } from "./classifier";
import type { AgentGateConfig, PolicyAction, PolicyDecision, ToolRisk, TrustState } from "./types";

export interface PolicyEvaluationInput {
  tool: string;
  risk: ToolRisk;
  trust: TrustState;
  config: AgentGateConfig;
  nonInteractive?: boolean;
  env?: NodeJS.ProcessEnv;
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
}

export function resolvePolicyAction(tool: string, config: AgentGateConfig): PolicyAction {
  if (config.policy.tools[tool]) return config.policy.tools[tool];
  for (const [pattern, action] of Object.entries(config.policy.tools)) {
    if (minimatch(tool, pattern)) return action;
  }
  return config.policy.default;
}

export async function evaluatePolicy(input: PolicyEvaluationInput): Promise<PolicyDecision> {
  const policyAction = resolvePolicyAction(input.tool, input.config);

  if (policyAction === "allow") {
    return { policy_action: policyAction, allowed: true, reason: "policy allowed tool call" };
  }

  if (policyAction === "record_only") {
    return {
      policy_action: policyAction,
      allowed: true,
      reason: "policy record_only allowed tool call"
    };
  }

  if (policyAction === "block") {
    return { policy_action: policyAction, allowed: false, reason: "policy blocked tool call" };
  }

  if (policyAction === "require_approval") {
    return evaluateApproval(input, policyAction);
  }

  const threshold = input.config.policy.tainted_block_threshold;
  if (input.trust.tainted && severityAtLeast(input.risk.severity, threshold)) {
    return {
      policy_action: policyAction,
      allowed: false,
      reason: `blocked ${input.risk.severity}-risk tool call because session is tainted`
    };
  }

  return {
    policy_action: policyAction,
    allowed: true,
    reason: input.trust.tainted
      ? `session is tainted but ${input.risk.severity}-risk tool call is allowed`
      : "session is not tainted"
  };
}

async function evaluateApproval(
  input: PolicyEvaluationInput,
  policyAction: PolicyAction
): Promise<PolicyDecision> {
  const env = input.env ?? process.env;
  const nonInteractive =
    Boolean(env.CI) ||
    (input.nonInteractive ?? false) ||
    !(input.input ?? process.stdin).isTTY ||
    !(input.output ?? process.stdout).isTTY;

  if (nonInteractive) {
    return {
      policy_action: policyAction,
      allowed: false,
      reason: "approval required but session is non-interactive or CI"
    };
  }

  const rl = createInterface({
    input: input.input ?? process.stdin,
    output: input.output ?? process.stdout
  });

  try {
    const answer = await rl.question(
      `AgentGate approval required for ${input.tool} (${input.risk.severity}). Approve? [y/N] `
    );
    const allowed = /^y(?:es)?$/i.test(answer.trim());
    return {
      policy_action: policyAction,
      allowed,
      reason: allowed ? "user approved privileged tool call" : "user denied privileged tool call"
    };
  } finally {
    rl.close();
  }
}
