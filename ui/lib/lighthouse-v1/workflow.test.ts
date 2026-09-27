import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  getProviderCredentials,
  getTenantConfig,
} from "@/actions/lighthouse-v1/lighthouse";
import { isVrikaEmbedMode } from "@/lib/vrika-embed";
import { fetchVrikaServerLlmConfig } from "@/lib/vrika-embed-lighthouse";

import { createLLM } from "./llm-factory";
import { initLighthouseWorkflow } from "./workflow";

vi.mock("langchain", () => ({ createAgent: vi.fn(() => "test-agent") }));
vi.mock("@/actions/lighthouse-v1/lighthouse", () => ({
  getProviderCredentials: vi.fn(),
  getTenantConfig: vi.fn(),
}));
vi.mock("@/lib/vrika-embed", () => ({ isVrikaEmbedMode: vi.fn() }));
vi.mock("@/lib/vrika-embed-lighthouse", () => ({
  fetchVrikaServerLlmConfig: vi.fn(),
  resolveOpenRouterLlmRouting: vi.fn((provider, _key, baseUrl) => ({
    provider,
    baseUrl,
  })),
}));
vi.mock("./llm-factory", () => ({ createLLM: vi.fn() }));
vi.mock("./agent-budget", () => ({ createAgentBudget: vi.fn() }));
vi.mock("./mcp-client", () => ({
  initializeMCPClient: vi.fn(),
  isMCPAvailable: vi.fn(() => false),
  getMCPTools: vi.fn(() => []),
}));
vi.mock("./skills/index", () => ({ getAllSkillMetadata: vi.fn(() => []) }));
vi.mock("./tools/load-skill", () => ({ loadSkill: {} }));
vi.mock("./tools/meta-tool", () => ({ describeTool: {}, executeTool: {} }));
vi.mock("./utils", () => ({ getModelParams: vi.fn(() => ({})) }));

describe("project-scoped embedded chat workflow", () => {
  beforeEach(() => {
    vi.mocked(isVrikaEmbedMode).mockReturnValue(true);
    vi.mocked(fetchVrikaServerLlmConfig).mockResolvedValue({
      provider: "openai_compatible",
      model: "organization/model",
      apiKey: "server-only-test-key",
      baseUrl: "https://model.example.test/v1",
    });
    vi.mocked(getTenantConfig).mockResolvedValue({ data: { attributes: {} } });
    vi.mocked(getProviderCredentials).mockResolvedValue({ credentials: {} });
  });

  it("uses managed config without reading or provisioning tenant-wide settings", async () => {
    await initLighthouseWorkflow();
    expect(getTenantConfig).not.toHaveBeenCalled();
    expect(getProviderCredentials).not.toHaveBeenCalled();
    expect(createLLM).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "openai_compatible",
        model: "organization/model",
        credentials: { api_key: "server-only-test-key" },
        baseUrl: "https://model.example.test/v1",
      }),
    );
  });

  it("does not let an embedded browser override the managed model/provider", async () => {
    await initLighthouseWorkflow({
      provider: "openai",
      model: "arbitrary-model",
    });
    expect(createLLM).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "openai_compatible",
        model: "organization/model",
      }),
    );
  });

  it("stops before model execution when project access or config resolution fails", async () => {
    vi.mocked(fetchVrikaServerLlmConfig).mockRejectedValue(
      new Error("Cloud Security access denied"),
    );
    await expect(initLighthouseWorkflow()).rejects.toThrow("access denied");
    expect(createLLM).not.toHaveBeenCalled();
  });

  it("preserves standalone provider/model selection", async () => {
    vi.mocked(isVrikaEmbedMode).mockReturnValue(false);
    vi.mocked(getProviderCredentials).mockResolvedValue({
      credentials: { api_key: "standalone-key" },
    });
    await initLighthouseWorkflow({
      provider: "openai",
      model: "standalone-model",
    });
    expect(fetchVrikaServerLlmConfig).not.toHaveBeenCalled();
    expect(createLLM).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "openai",
        model: "standalone-model",
        credentials: { api_key: "standalone-key" },
      }),
    );
  });
});
