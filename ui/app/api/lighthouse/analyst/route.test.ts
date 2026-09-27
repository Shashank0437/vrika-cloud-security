import { beforeEach, describe, expect, it, vi } from "vitest";

import { getTenantConfig } from "@/actions/lighthouse-v1/lighthouse";
import { getAuthContext } from "@/lib/lighthouse-v1/auth-context";
import { initLighthouseWorkflow } from "@/lib/lighthouse-v1/workflow";
import { VrikaAiConfigurationError } from "@/lib/vrika-embed-lighthouse";

import { POST } from "./route";

const { authMock } = vi.hoisted(() => ({ authMock: vi.fn() }));
vi.mock("server-only", () => ({}));
vi.mock("@/auth.config", () => ({ auth: authMock }));
vi.mock("@sentry/nextjs", () => ({ captureException: vi.fn() }));
vi.mock("@/actions/lighthouse-v1/lighthouse", () => ({
  getTenantConfig: vi.fn(),
}));
vi.mock("@/lib/lighthouse-v1/data", () => ({
  getCurrentDataSection: vi.fn(() => ""),
}));
vi.mock("@/lib/lighthouse-v1/workflow", () => ({
  initLighthouseWorkflow: vi.fn(),
}));
vi.mock("@/lib/lighthouse-v1/utils", () => ({
  convertVercelMessageToLangChainMessage: vi.fn((message) => message),
}));
vi.mock("@/lib/vrika-embed", () => ({ isVrikaEmbedMode: () => true }));
vi.mock("@/lib/helper", () => ({
  apiBaseUrl: "http://cloud-api/api/v1",
  getErrorMessage: () => "Request failed",
}));

function request() {
  return new Request("http://cloud-ui/api/lighthouse/analyst", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      messages: [{ role: "user", parts: [{ type: "text", text: "hello" }] }],
    }),
  });
}

describe("embedded analyst endpoint", () => {
  beforeEach(() => {
    authMock.mockResolvedValue({ accessToken: "project-scoped-test-token" });
  });

  it("rejects anonymous requests before resolving the model", async () => {
    authMock.mockResolvedValue(null);
    expect((await POST(request())).status).toBe(401);
    expect(initLighthouseWorkflow).not.toHaveBeenCalled();
  });

  it("preserves the scoped token and skips tenant-wide business context", async () => {
    vi.mocked(initLighthouseWorkflow).mockImplementation(async () => {
      expect(getAuthContext()).toBe("project-scoped-test-token");
      throw new VrikaAiConfigurationError(
        "Cloud Security access revoked.",
        403,
      );
    });
    const response = await POST(request());
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: "Cloud Security access revoked.",
    });
    expect(getTenantConfig).not.toHaveBeenCalled();
    expect(getAuthContext()).toBeNull();
  });
});
