# Security Policy

AgentGate is a local tool-call firewall for AI agents. Please report vulnerabilities privately when possible.

## Reporting a Vulnerability

Use GitHub Security Advisories for this repository if available:

https://github.com/shooter-jp/agent-gate/security/advisories

If advisories are not available, open a minimal GitHub issue that states you have a security report without including exploit details, secrets, or private target information.

## Scope

In scope:

- Bypasses of tainted-session blocking.
- Trace redaction failures for common credential patterns.
- JSON-RPC or MCP proxy behavior that can corrupt client/server communication.
- Replay behavior that incorrectly passes a blocked-call regression.

Out of scope:

- Hosted service, dashboard, database, telemetry, or cloud issues. AgentGate does not provide those components.
- Vulnerabilities in third-party MCP servers or agents unless AgentGate directly causes the unsafe behavior.
