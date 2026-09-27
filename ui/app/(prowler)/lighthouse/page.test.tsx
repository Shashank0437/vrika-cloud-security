import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  getLighthouseProvidersConfig,
  isLighthouseConfigured,
} from "@/actions/lighthouse-v1/lighthouse";
import {
  fetchVrikaServerLlmConfig,
  VrikaAiConfigurationError,
} from "@/lib/vrika-embed-lighthouse";

import AIChatbot from "./page";

vi.mock("server-only", () => ({}));
vi.mock("@/auth.config", () => ({ auth: vi.fn() }));
vi.mock("@/lib/helper", () => ({ apiBaseUrl: "http://cloud-api/api/v1" }));
vi.mock("@/actions/lighthouse-v1/lighthouse", () => ({
  getLighthouseProvidersConfig: vi.fn(),
  isLighthouseConfigured: vi.fn(),
}));
vi.mock("@/lib/shared/env", () => ({ isCloud: () => false }));
vi.mock("@/lib/vrika-embed", () => ({
  isVrikaEmbedMode: () => true,
  getVrikaAiLabel: () => "Vrika AI",
}));
vi.mock("@/lib/vrika-embed-lighthouse", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/vrika-embed-lighthouse")>()),
  fetchVrikaServerLlmConfig: vi.fn(),
}));
vi.mock("@/components/lighthouse-v1", () => ({
  Chat: (props: Record<string, unknown>) => (
    <pre data-testid="chat-props">{JSON.stringify(props)}</pre>
  ),
}));
vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({ children }: { children: ReactNode }) => (
    <main>{children}</main>
  ),
}));
vi.mock("@/components/icons/Icons", () => ({ LighthouseIcon: () => null }));
vi.mock("./_actions", () => ({}));
vi.mock("./_components/chat", () => ({ LighthouseV2ChatPage: () => null }));
vi.mock("./_components/navigation", () => ({
  LighthouseV2NavigationModeSync: () => null,
}));
vi.mock("./_lib/model-loading", () => ({}));

describe("embedded project AI page", () => {
  beforeEach(() => {
    vi.mocked(fetchVrikaServerLlmConfig).mockResolvedValue({
      apiKey: "must-never-reach-browser",
      provider: "openai_compatible",
      model: "organization/model",
      baseUrl: "http://private-model",
    });
  });

  it("renders usable chat without tenant settings calls or secret props", async () => {
    render(
      await AIChatbot({
        searchParams: Promise.resolve({ prompt: "Analyze finding" }),
      }),
    );
    const props = screen.getByTestId("chat-props").textContent;
    expect(props).toContain('"hasConfig":true');
    expect(props).toContain('"initialPrompt":"Analyze finding"');
    expect(props).toContain('"defaultModelId":"organization/model"');
    expect(props).not.toContain("must-never-reach-browser");
    expect(props).not.toContain("private-model");
    expect(isLighthouseConfigured).not.toHaveBeenCalled();
    expect(getLighthouseProvidersConfig).not.toHaveBeenCalled();
  });

  it("shows an actionable unavailable state rather than a false missing-provider claim", async () => {
    vi.mocked(fetchVrikaServerLlmConfig).mockRejectedValue(
      new VrikaAiConfigurationError(
        "Project access could not be verified.",
        403,
      ),
    );
    render(await AIChatbot({ searchParams: Promise.resolve({}) }));
    expect(screen.getByTestId("chat-props")).toHaveTextContent(
      '"hasConfig":false',
    );
    expect(screen.getByTestId("chat-props")).toHaveTextContent(
      "Project access could not be verified.",
    );
    expect(isLighthouseConfigured).not.toHaveBeenCalled();
  });
});
