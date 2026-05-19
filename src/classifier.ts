import {
  severityOrder,
  type RiskSeverity,
  type ToolAction,
  type ToolDefinition,
  type ToolRisk
} from "./types";

interface KeywordGroup {
  action: ToolAction;
  severity: RiskSeverity;
  keywords: string[];
}

const keywordGroups: KeywordGroup[] = [
  {
    action: "read",
    severity: "low",
    keywords: ["read", "search", "list", "get", "fetch", "retrieve", "view"]
  },
  {
    action: "write",
    severity: "high",
    keywords: [
      "write",
      "create",
      "update",
      "commit",
      "pull_request",
      "pull request",
      "merge",
      "upload",
      "save"
    ]
  },
  {
    action: "send",
    severity: "high",
    keywords: [
      "send",
      "send email",
      "post",
      "post message",
      "publish",
      "publish message",
      "webhook",
      "notify",
      "external url",
      "external_url",
      "recipient",
      "recipients"
    ]
  },
  {
    action: "delete",
    severity: "critical",
    keywords: ["delete", "remove", "destroy", "drop", "truncate", "revoke"]
  },
  {
    action: "execute",
    severity: "critical",
    keywords: [
      "exec",
      "execute",
      "shell",
      "bash",
      "terminal",
      "command",
      "spawn",
      "subprocess",
      "run_command"
    ]
  },
  {
    action: "browser",
    severity: "high",
    keywords: ["browser", "click", "submit", "form", "navigate", "page"]
  },
  {
    action: "payment",
    severity: "critical",
    keywords: ["payment", "purchase", "checkout", "charge", "invoice", "transfer"]
  },
  {
    action: "database",
    severity: "critical",
    keywords: ["sql", "db", "update_sql", "execute_sql", "insert", "mutation"]
  }
];

const schemaKeywordGroups: KeywordGroup[] = keywordGroups.map((group) =>
  group.action === "browser"
    ? { ...group, keywords: group.keywords.filter((keyword) => keyword !== "page") }
    : group
);

function normalize(input: string): string {
  return input
    .toLowerCase()
    .replace(/[_./:-]+/g, " ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function hasPhrase(normalizedText: string, keyword: string): boolean {
  const normalizedKeyword = normalize(keyword);
  if (!normalizedKeyword) return false;
  const escaped = normalizedKeyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
  return new RegExp(`(^|\\s)${escaped}(\\s|$)`).test(normalizedText);
}

function severityRank(severity: RiskSeverity): number {
  return severityOrder.indexOf(severity);
}

export function classifyTool(tool: ToolDefinition | string, description = ""): ToolRisk {
  const name = typeof tool === "string" ? tool : tool.name;
  const toolDescription = typeof tool === "string" ? description : (tool.description ?? "");
  const inputSchema = typeof tool === "string" ? "" : (JSON.stringify(tool.inputSchema ?? {}) ?? "");
  const best = chooseBestMatch([
    findBestMatch(normalize(`${name} ${toolDescription}`), keywordGroups),
    findBestMatch(normalize(inputSchema), schemaKeywordGroups)
  ]);

  if (!best) {
    return {
      action: "unknown",
      severity: "medium",
      matched_keywords: []
    };
  }

  return {
    action: best.group.action,
    severity: best.group.severity,
    matched_keywords: best.matched
  };
}

function findBestMatch(
  normalizedText: string,
  groups: KeywordGroup[]
): { group: KeywordGroup; matched: string[]; longest: number } | undefined {
  let best: { group: KeywordGroup; matched: string[]; longest: number } | undefined;

  for (const group of groups) {
    const matched = group.keywords.filter((keyword) => hasPhrase(normalizedText, keyword));
    if (matched.length === 0) continue;
    const longest = Math.max(...matched.map((keyword) => normalize(keyword).length));
    if (!best) {
      best = { group, matched, longest };
      continue;
    }

    const severityDelta = severityRank(group.severity) - severityRank(best.group.severity);
    if (severityDelta > 0 || (severityDelta === 0 && longest > best.longest)) {
      best = { group, matched, longest };
    }
  }

  return best;
}

function chooseBestMatch(
  matches: Array<{ group: KeywordGroup; matched: string[]; longest: number } | undefined>
): { group: KeywordGroup; matched: string[]; longest: number } | undefined {
  return matches.reduce<{ group: KeywordGroup; matched: string[]; longest: number } | undefined>(
    (best, match) => {
      if (!match) return best;
      if (!best) return match;

      const severityDelta = severityRank(match.group.severity) - severityRank(best.group.severity);
      if (severityDelta > 0 || (severityDelta === 0 && match.longest > best.longest)) {
        return match;
      }

      return best;
    },
    undefined
  );
}

export function severityAtLeast(severity: RiskSeverity, threshold: RiskSeverity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}
