import { describe, expect, it } from "vitest";
import { classifyTool } from "../src/classifier";

describe("classifyTool", () => {
  it("classifies read tools as low risk", () => {
    expect(classifyTool("github.read_issue")).toMatchObject({
      action: "read",
      severity: "low"
    });
  });

  it("classifies privileged write tools as high risk", () => {
    expect(classifyTool("github.create_pull_request")).toMatchObject({
      action: "write",
      severity: "high"
    });
  });

  it("chooses critical severity over lower-severity matches", () => {
    expect(classifyTool("database.update_sql")).toMatchObject({
      action: "database",
      severity: "critical"
    });
  });

  it("defaults unknown tools to medium risk", () => {
    expect(classifyTool("acme.summarize")).toEqual({
      action: "unknown",
      severity: "medium",
      matched_keywords: []
    });
  });

  it("uses inputSchema when classifying send tools", () => {
    expect(
      classifyTool({
        name: "acme.deliver",
        inputSchema: {
          type: "object",
          properties: {
            recipient: { type: "string" },
            body: { type: "string" }
          }
        }
      })
    ).toMatchObject({
      action: "send",
      severity: "high"
    });
  });

  it("uses inputSchema when classifying write tools", () => {
    expect(
      classifyTool({
        name: "acme.prepare",
        inputSchema: {
          type: "object",
          properties: {
            commit_message: { type: "string" }
          }
        }
      })
    ).toMatchObject({
      action: "write",
      severity: "high"
    });
  });

  it("uses inputSchema when classifying execute tools", () => {
    expect(
      classifyTool({
        name: "acme.perform",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string" }
          }
        }
      })
    ).toMatchObject({
      action: "execute",
      severity: "critical"
    });
  });

  it("splits camelCase and PascalCase schema fields before matching", () => {
    expect(
      classifyTool({
        name: "acme.perform",
        inputSchema: {
          type: "object",
          properties: {
            runCommand: { type: "string" }
          }
        }
      })
    ).toMatchObject({ action: "execute", severity: "critical" });

    expect(
      classifyTool({
        name: "acme.deliver",
        inputSchema: {
          type: "object",
          properties: {
            externalUrl: { type: "string" }
          }
        }
      })
    ).toMatchObject({ action: "send", severity: "high" });

    expect(
      classifyTool({
        name: "acme.query",
        inputSchema: {
          type: "object",
          properties: {
            sqlQuery: { type: "string" }
          }
        }
      })
    ).toMatchObject({ action: "database", severity: "critical" });

    expect(
      classifyTool({
        name: "acme.prepare",
        inputSchema: {
          type: "object",
          properties: {
            pullRequest: { type: "string" }
          }
        }
      })
    ).toMatchObject({ action: "write", severity: "high" });

    expect(
      classifyTool({
        name: "acme.notify",
        inputSchema: {
          type: "object",
          properties: {
            recipientEmail: { type: "string" }
          }
        }
      })
    ).toMatchObject({ action: "send", severity: "high" });
  });

  it("does not treat bare post nouns as send indicators", () => {
    expect(classifyTool("blog.get_post")).toMatchObject({
      action: "read",
      severity: "low"
    });
    expect(classifyTool("forum.search_posts")).toMatchObject({
      action: "read",
      severity: "low"
    });
    expect(classifyTool("slack.post_message")).toMatchObject({
      action: "send",
      severity: "high"
    });
    expect(classifyTool("social.post")).toMatchObject({
      action: "send",
      severity: "high"
    });
    expect(classifyTool("twitter.post_tweet")).toMatchObject({
      action: "send",
      severity: "high"
    });
  });

  it("does not treat pagination schema fields as browser indicators", () => {
    expect(
      classifyTool({
        name: "github.search_issues",
        description: "Search GitHub issues.",
        inputSchema: {
          type: "object",
          properties: {
            page: { type: "number" },
            page_size: { type: "number" },
            query: { type: "string" }
          }
        }
      })
    ).toMatchObject({
      action: "read",
      severity: "low"
    });
  });

  it("does not treat service nouns as send indicators", () => {
    expect(classifyTool("slack.search_messages")).toMatchObject({
      action: "read",
      severity: "low"
    });
    expect(classifyTool("gmail.search_email")).toMatchObject({
      action: "read",
      severity: "low"
    });
  });

  it("does not treat returned content body as a send indicator", () => {
    expect(
      classifyTool("github.read_issue", "Read a GitHub issue and return the issue body.")
    ).toMatchObject({
      action: "read",
      severity: "low"
    });
  });
});
