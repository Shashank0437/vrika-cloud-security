import { beforeEach, describe, expect, it, vi } from "vitest";

import { fetchVrikaServerLlmConfig } from "./vrika-embed-lighthouse";

const { authMock } = vi.hoisted(() => ({ authMock: vi.fn() }));
vi.mock("server-only", () => ({}));
vi.mock("@/auth.config", () => ({ auth: authMock }));
vi.mock("@/lib/helper", () => ({ apiBaseUrl: "http://cloud-api/api/v1" }));

const fetchMock = vi.fn();
const accessToken = [
  "header",
  Buffer.from(JSON.stringify({ tenant_id: "tenant-a" })).toString("base64url"),
  "signature",
].join(".");

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

describe("embedded organization model configuration", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("VRIKA_BRIDGE_SECRET", "test-bridge-secret");
    vi.stubEnv("VRIKA_SERVER_API_URL", "http://vrika-api:8000");
    authMock.mockResolvedValue({ accessToken });
    fetchMock
      .mockResolvedValueOnce(response({ data: { id: "user-a" } }))
      .mockResolvedValueOnce(
        response({
          llm: {
            provider: "openrouter",
            api_key: "test-model-key",
            model: "example/model",
          },
          smtp: { password: "not-part-of-model-config" },
        }),
      );
  });

  it("validates project access and resolves only the authenticated token's tenant", async () => {
    expect(await fetchVrikaServerLlmConfig()).toEqual({
      apiKey: "test-model-key",
      provider: "openai_compatible",
      model: "example/model",
      baseUrl: "https://openrouter.ai/api/v1",
    });
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "http://cloud-api/api/v1/users/me",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: `Bearer ${accessToken}`,
        }),
        cache: "no-store",
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "http://vrika-api:8000/internal/org-config?prowler_tenant_id=tenant-a",
      expect.objectContaining({
        headers: { "X-Vrika-Internal-Secret": "test-bridge-secret" },
        cache: "no-store",
      }),
    );
    expect(
      fetchMock.mock.calls.every(([url]) => !url.includes("secret=")),
    ).toBe(true);
  });

  it("does not fetch credentials without a signed-in user", async () => {
    authMock.mockResolvedValue(null);
    await expect(fetchVrikaServerLlmConfig()).rejects.toThrow("Sign in");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([401, 403])(
    "rejects invalid or revoked project access (%s)",
    async (status) => {
      fetchMock.mockReset().mockResolvedValueOnce(response({}, status));
      await expect(fetchVrikaServerLlmConfig()).rejects.toThrow(
        "Cloud Security access",
      );
      expect(fetchMock).toHaveBeenCalledTimes(1);
    },
  );

  it("does not use stale session tenant metadata", async () => {
    authMock.mockResolvedValue({
      accessToken,
      tenantId: "another-tenant",
    });
    await fetchVrikaServerLlmConfig();
    expect(fetchMock.mock.calls[1][0]).toContain("prowler_tenant_id=tenant-a");
  });

  it("resolves a second tenant independently without reusing the first model", async () => {
    await fetchVrikaServerLlmConfig();
    const otherToken = [
      "header",
      Buffer.from(JSON.stringify({ tenant_id: "tenant-b" })).toString(
        "base64url",
      ),
      "signature",
    ].join(".");
    authMock.mockResolvedValue({ accessToken: otherToken });
    fetchMock
      .mockResolvedValueOnce(response({ data: { id: "user-b" } }))
      .mockResolvedValueOnce(
        response({
          llm: {
            provider: "openai",
            api_key: "second-key",
            model: "second-model",
          },
        }),
      );
    expect(await fetchVrikaServerLlmConfig()).toMatchObject({
      apiKey: "second-key",
      model: "second-model",
    });
    expect(fetchMock.mock.calls[3][0]).toContain("prowler_tenant_id=tenant-b");
  });

  it("fails closed when the bridge secret is missing", async () => {
    vi.stubEnv("VRIKA_BRIDGE_SECRET", "");
    vi.stubEnv("VRIKA_INTERNAL_CONFIG_SECRET", "");
    await expect(fetchVrikaServerLlmConfig()).rejects.toThrow(
      "connection is not configured",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not resolve credentials after a Cloud API outage", async () => {
    fetchMock.mockReset().mockResolvedValueOnce(response({}, 500));
    await expect(fetchVrikaServerLlmConfig()).rejects.toThrow(
      "access could not be verified",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not use another organization's model or environment fallback", async () => {
    vi.stubEnv("VRIKA_LLM_API_KEY", "unrelated-environment-key");
    fetchMock
      .mockReset()
      .mockResolvedValueOnce(response({ data: {} }))
      .mockResolvedValueOnce(response({}));
    await expect(fetchVrikaServerLlmConfig()).rejects.toThrow("not configured");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("surfaces bridge failures without exposing its response body", async () => {
    fetchMock
      .mockReset()
      .mockResolvedValueOnce(response({ data: {} }))
      .mockResolvedValueOnce(
        response({ error: "private-backend-details" }, 503),
      );
    await expect(fetchVrikaServerLlmConfig()).rejects.toThrow(
      "Cloud Security AI configuration could not be loaded",
    );
  });

  it("requires an explicit model instead of silently choosing a default", async () => {
    fetchMock
      .mockReset()
      .mockResolvedValueOnce(response({ data: {} }))
      .mockResolvedValueOnce(
        response({ llm: { provider: "openai", api_key: "key" } }),
      );
    await expect(fetchVrikaServerLlmConfig()).rejects.toThrow("not configured");
  });
});
