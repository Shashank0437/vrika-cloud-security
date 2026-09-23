import { type StructuredTool, tool } from "@langchain/core/tools";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { authContextStorage } from "./auth-context";
import {
  getMCPToolByName,
  initializeMCPClient,
  resetMCPClient,
} from "./mcp-client";
import { getCanonicalToolName, isAllowedTool } from "./tool-policy";
import { describeTool, executeTool } from "./tools/meta-tool";

vi.mock("server-only", () => ({}));
vi.mock("@sentry/nextjs", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
  captureMessage: vi.fn(),
}));

interface ToolCallInput {
  serverName: string;
  name: string;
  args?: unknown;
}

interface ToolCallResult {
  args?: unknown;
  headers?: Record<string, string>;
}

let beforeToolCall: (input: ToolCallInput) => ToolCallResult;
const invokeScan = vi.fn();
const scanTool: StructuredTool = tool(invokeScan, {
  name: "prowler_list_attack_paths_scans",
  description: "List completed cloud graph scans",
  schema: z.object({ provider_type: z.array(z.string()) }),
});

vi.mock("@langchain/mcp-adapters", () => ({
  MultiServerMCPClient: class {
    constructor(options: { beforeToolCall: typeof beforeToolCall }) {
      beforeToolCall = options.beforeToolCall;
    }
    async getTools() {
      return [scanTool];
    }
  },
}));

describe("MCP namespace compatibility", () => {
  beforeEach(async () => {
    resetMCPClient();
    scanTool.name = "prowler_list_attack_paths_scans";
    vi.stubEnv("PROWLER_MCP_SERVER_URL", "http://isolated-mcp/mcp");
    invokeScan.mockResolvedValue({ scans: [] });
    await initializeMCPClient();
  });

  it("preserves compatibility with canonical-name MCP servers", async () => {
    scanTool.name = "prowler_app_list_attack_paths_scans";
    expect(getMCPToolByName(scanTool.name)).toBe(scanTool);
    expect(getMCPToolByName("prowler_list_attack_paths_scans")).toBe(scanTool);
    expect(
      await describeTool.invoke({ toolName: scanTool.name }),
    ).toMatchObject({
      found: true,
      name: scanTool.name,
    });
  });

  it("resolves the canonical name to the deployed tool without renaming its wire name", () => {
    expect(getMCPToolByName("prowler_app_list_attack_paths_scans")).toBe(
      scanTool,
    );
    expect(scanTool.name).toBe("prowler_list_attack_paths_scans");
    expect(getCanonicalToolName(scanTool.name)).toBe(
      "prowler_app_list_attack_paths_scans",
    );
  });

  it("describes and executes the canonical account-analysis tool", async () => {
    const description = await describeTool.invoke({
      toolName: "prowler_app_list_attack_paths_scans",
    });
    expect(description).toMatchObject({
      found: true,
      name: "prowler_app_list_attack_paths_scans",
    });
    expect(
      await executeTool.invoke({
        toolName: "prowler_app_list_attack_paths_scans",
        toolInput: { provider_type: ["aws"] },
      }),
    ).toMatchObject({ success: true, result: { scans: [] } });
    expect(invokeScan).toHaveBeenCalledTimes(1);
  });

  it.each([
    "prowler_list_attack_paths_scans",
    "prowler_app_list_attack_paths_scans",
  ])("forwards only the current request's auth for %s", async (name) => {
    const call = { serverName: "prowler", name, args: {} };
    const results = await Promise.all(
      ["tenant-a-test-token", "tenant-b-test-token"].map((token) =>
        authContextStorage.run(token, async () => {
          await Promise.resolve();
          return beforeToolCall(call);
        }),
      ),
    );
    expect(results.map((result) => result.headers?.Authorization)).toEqual([
      "Bearer tenant-a-test-token",
      "Bearer tenant-b-test-token",
    ]);
    expect(beforeToolCall(call).headers).toBeUndefined();
  });

  it.each([
    "prowler_hub_list_checks",
    "prowler_docs_search",
    "prowler_unknown_tool",
  ])("does not forward tenant credentials to %s", (name) => {
    const result = authContextStorage.run("isolated-token", () =>
      beforeToolCall({ serverName: "prowler", name }),
    );
    expect(result.headers).toBeUndefined();
  });

  it.each([
    "prowler_trigger_scan",
    "prowler_app_trigger_scan",
    "prowler_delete_provider",
    "prowler_app_delete_provider",
  ])("keeps write tools blocked: %s", async (name) => {
    expect(isAllowedTool(name)).toBe(false);
    expect(
      await executeTool.invoke({ toolName: name, toolInput: {} }),
    ).toHaveProperty("error");
    expect(invokeScan).not.toHaveBeenCalled();
  });
});
