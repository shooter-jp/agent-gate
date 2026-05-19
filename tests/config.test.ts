import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { configToYaml, exampleConfig } from "../src/config";

describe("config", () => {
  it("renders a neutral default config for init", () => {
    const yaml = configToYaml();
    const parsed = parseYaml(yaml) as Record<string, unknown>;

    expect(parsed).toMatchObject({
      project: "agentgate",
      trace_dir: ".agentgate/traces",
      untrusted_tools: [],
      policy: {
        default: "block_when_tainted",
        tainted_block_threshold: "medium",
        tools: {}
      },
      servers: {}
    });
    expect(parsed.tools_fixture).toBeUndefined();
    expect(yaml).not.toContain("examples/");
  });

  it("keeps repo-local example config separate from the init default", () => {
    const parsed = parseYaml(configToYaml(exampleConfig)) as Record<string, unknown>;

    expect(parsed).toMatchObject({
      servers: {
        github: {
          command: "node",
          args: ["examples/mock-github-server.mjs"]
        }
      },
      tools_fixture: "examples/tools/github-tools.json"
    });
  });
});
