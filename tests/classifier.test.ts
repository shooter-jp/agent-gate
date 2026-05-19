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
});
