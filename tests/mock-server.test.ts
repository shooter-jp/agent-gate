import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const servers: ChildProcessWithoutNullStreams[] = [];

afterEach(() => {
  for (const server of servers.splice(0)) {
    server.kill();
  }
});

describe("mock GitHub MCP server", () => {
  it("responds to initialize and ignores initialized notifications", async () => {
    const server = spawn(process.execPath, [path.resolve("examples/mock-github-server.mjs")], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    servers.push(server);
    const output = lineReader(server.stdout);

    server.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-11-25" }
      })}\n`
    );

    expect(JSON.parse(await output.nextLine())).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-11-25",
        capabilities: { tools: { listChanged: true } },
        serverInfo: {
          name: "agentgate-mock-github",
          version: "0.1.0"
        }
      }
    });

    server.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`
    );
    await waitForSettled();
    expect(output.lines()).toEqual([]);
  });
});

function lineReader(stream: NodeJS.ReadableStream) {
  const lines: string[] = [];
  const waiters: Array<(line: string) => void> = [];
  let buffer = "";
  stream.on("data", (chunk) => {
    buffer += chunk.toString();
    let newline = buffer.indexOf("\n");
    while (newline >= 0) {
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      const waiter = waiters.shift();
      if (waiter) waiter(line);
      else lines.push(line);
      newline = buffer.indexOf("\n");
    }
  });

  return {
    lines: () => [...lines],
    nextLine: (timeoutMs = 1000) =>
      new Promise<string>((resolve, reject) => {
        const existing = lines.shift();
        if (existing !== undefined) {
          resolve(existing);
          return;
        }
        const timeout = setTimeout(
          () => reject(new Error("Timed out waiting for line")),
          timeoutMs
        );
        waiters.push((line) => {
          clearTimeout(timeout);
          resolve(line);
        });
      })
  };
}

function waitForSettled(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 10));
}
