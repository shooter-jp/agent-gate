# AgentGate

Stop untrusted content from triggering privileged tool calls.

AgentGate is the tool-call firewall for AI agents. It sits between your local agent and MCP tools, blocks write/send/delete/exec-style calls after untrusted content enters the session, records the trace, and turns that trace into a regression test.

AgentGate is a focused developer CLI. It is not a SaaS dashboard, database-backed security platform, telemetry product, or agent framework.

## Install

```bash
pnpm install
pnpm build
```

After publishing, the intended install path is:

```bash
pnpm add -D agentgate
```

This MVP targets Node.js 20+ and uses a minimal line-delimited STDIO JSON-RPC proxy instead of a full MCP SDK integration.

## 60-second demo

```bash
node dist/cli.js demo github-injection
node dist/cli.js replay .agentgate/traces
```

The demo runs with no credentials or network services. It simulates a GitHub issue that contains prompt-injection text, then simulates an attempted privileged GitHub write. AgentGate marks the session tainted and blocks the write.

## Use with Codex

Codex supports local STDIO MCP servers. After building AgentGate from source, register the proxy in Codex:

```bash
codex mcp add agentgate-github -- node dist/cli.js proxy \
  --config examples/agentgate.yml \
  --server github
```

After npm publishing, the intended one-command setup is:

```bash
codex mcp add agentgate-github -- npx -y agentgate proxy \
  --config agentgate.yml \
  --server github
```

## Why it exists

AI agents often read untrusted content before calling privileged tools. AgentGate gives local developers a narrow firewall for that boundary:

- classify tool risk deterministically
- taint a session after untrusted or suspicious tool output
- block medium, high, and critical tool calls once tainted
- write a redacted trace
- replay the trace as a regression test

## Commands

```bash
agentgate init
agentgate scan [configOrToolsPath] [--json] [--fail-on high|critical]
agentgate proxy --config agentgate.yml [--server github]
agentgate replay <tracePathOrDir>
agentgate demo github-injection
agentgate doctor
```

## Config example

```yaml
project: agentgate-example
trace_dir: .agentgate/traces
untrusted_tools:
  - github.read_*
policy:
  default: block_when_tainted
  tainted_block_threshold: medium
  tools:
    github.create_*: block_when_tainted
    github.write_*: block_when_tainted
servers:
  github:
    command: node
    args: ["examples/mock-github-server.mjs"]
tools_fixture: examples/tools/github-tools.json
```

## Trace example

Traces are written to `.agentgate/traces` by default and are never uploaded. Arguments are redacted before writing, and results are stored as hashes.

```json
{
  "trace_id": "ag_20260519000000_abcd1234",
  "schema_version": "1.0",
  "project": "agentgate-demo",
  "agentgate_version": "0.1.0",
  "policy_hash": "sha256:...",
  "tool_inventory_hash": "sha256:...",
  "server": "github",
  "mcp_protocol_version": "2025-11-25",
  "started_at": "2026-05-19T00:00:00.000Z",
  "ended_at": "2026-05-19T00:00:01.000Z",
  "inventory_complete": true,
  "events": [
    {
      "type": "tool_call",
      "tool": "github.create_pull_request",
      "arguments": { "title": "Security update", "body": "[REDACTED]" },
      "risk": {
        "action": "write",
        "severity": "high",
        "matched_keywords": ["create", "pull_request"]
      },
      "decision": {
        "policy_action": "block_when_tainted",
        "allowed": false,
        "reason": "blocked high-risk tool call because session is tainted"
      },
      "tool_schema_hash": "sha256:...",
      "expected_decision": "blocked",
      "result_hash": null
    }
  ]
}
```

## Security model

AgentGate uses conservative deterministic rules:

- Sessions start untainted.
- Tool results from configured untrusted tools taint the session.
- Tool results containing suspicious prompt-injection text taint the session.
- Once tainted, `block_when_tainted` blocks medium, high, and critical tool calls by default.
- Set `policy.tainted_block_threshold` to tune that fail-closed threshold.
- `require_approval` blocks in CI and non-interactive mode; in an interactive terminal it asks with default No.
- Proxy mode always evaluates policy non-interactively, so stdout remains newline-delimited JSON-RPC only.

Suspicious text includes phrases such as `ignore previous instructions`, `system prompt`, `reveal secrets`, `exfiltrate`, `post to webhook`, `base64`, and `hidden instruction`.

## Limitations

- AgentGate does not perform semantic influence tracking.
- The first proxy implementation uses newline-delimited JSON-RPC, not MCP Content-Length framing.
- JSON-RPC batch requests are not supported in the first proxy implementation.
- Policy is local and file-based.
- Trace files contain redacted arguments, evidence snippets, hashes, and decisions, not full tool results.
- The demo server in `examples/mock-github-server.mjs` is a minimal MCP-compatible local fixture, not a production GitHub MCP server.

## Roadmap

- MCP Content-Length framing support.
- Broader fixture formats for common MCP servers.
- More policy diagnostics in replay.
- Optional generated regression test templates from traces.

## License

Apache-2.0
