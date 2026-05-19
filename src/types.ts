export const severityOrder = ["low", "medium", "high", "critical"] as const;
export type RiskSeverity = (typeof severityOrder)[number];

export const actionOrder = [
  "read",
  "write",
  "send",
  "delete",
  "execute",
  "browser",
  "payment",
  "database",
  "unknown"
] as const;
export type ToolAction = (typeof actionOrder)[number];

export const policyActions = [
  "allow",
  "block",
  "require_approval",
  "block_when_tainted",
  "record_only"
] as const;
export type PolicyAction = (typeof policyActions)[number];

export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface ToolRisk {
  action: ToolAction;
  severity: RiskSeverity;
  matched_keywords: string[];
}

export interface PolicyConfig {
  default: PolicyAction;
  tools: Record<string, PolicyAction>;
}

export interface ServerConfig {
  command: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string>;
}

export interface AgentGateConfig {
  project: string;
  trace_dir: string;
  untrusted_tools: string[];
  policy: PolicyConfig;
  servers: Record<string, ServerConfig>;
  tools_fixture?: string;
}

export interface LoadedConfig {
  config: AgentGateConfig;
  path?: string;
  baseDir: string;
}

export interface TrustEvidence {
  tool: string;
  reason: string;
  evidence: string;
}

export interface TrustState {
  tainted: boolean;
  sources: TrustEvidence[];
}

export interface PolicyDecision {
  policy_action: PolicyAction;
  allowed: boolean;
  reason: string;
}

export interface TraceEvent {
  tool: string;
  arguments: unknown;
  risk: ToolRisk;
  trust: {
    before: TrustState;
    after: TrustState;
  };
  decision: PolicyDecision;
  reason: string;
  evidence?: string;
  result_hash: string | null;
}

export interface TraceFile {
  trace_id: string;
  schema_version: "1.0";
  project: string;
  started_at: string;
  ended_at: string | null;
  inventory?: Array<ToolDefinition & { risk: ToolRisk }>;
  events: TraceEvent[];
}
