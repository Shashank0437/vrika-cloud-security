import "server-only";

import { jwtDecode } from "jwt-decode";
import { z } from "zod";

import { auth } from "@/auth.config";
import { apiBaseUrl } from "@/lib/helper";
import type { LighthouseProvider } from "@/types/lighthouse-v1";

/** Map platform LLM provider names (e.g. openrouter) to Prowler Lighthouse types. */
export function normalizeLighthouseProvider(
  raw: string | undefined,
  usingOpenRouter: boolean,
  hasCustomBaseUrl: boolean,
): LighthouseProvider {
  const value = raw?.trim().toLowerCase();
  if (value === "bedrock") {
    return "bedrock";
  }
  if (
    value === "openai_compatible" ||
    value === "openai-compatible" ||
    value === "openrouter"
  ) {
    return "openai_compatible";
  }
  if (value === "openai") {
    return usingOpenRouter || hasCustomBaseUrl ? "openai_compatible" : "openai";
  }
  if (usingOpenRouter || hasCustomBaseUrl) {
    return "openai_compatible";
  }
  return "openai";
}

const OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1";

export function isOpenRouterApiKey(apiKey?: string): boolean {
  return apiKey?.startsWith("sk-or-") ?? false;
}

/** OpenRouter keys must use openai_compatible + base URL, not the OpenAI endpoint. */
export function resolveOpenRouterLlmRouting(
  provider: LighthouseProvider,
  apiKey: string | undefined,
  baseUrl: string | undefined,
): { provider: LighthouseProvider; baseUrl: string | undefined } {
  const useOpenRouter =
    isOpenRouterApiKey(apiKey) || baseUrl?.includes("openrouter.ai") === true;

  if (useOpenRouter && provider === "openai") {
    return {
      provider: "openai_compatible",
      baseUrl: baseUrl || OPENROUTER_BASE_URL,
    };
  }

  if (
    provider === "openai_compatible" &&
    !baseUrl &&
    isOpenRouterApiKey(apiKey)
  ) {
    return { provider, baseUrl: OPENROUTER_BASE_URL };
  }

  return { provider, baseUrl };
}

export class VrikaAiConfigurationError extends Error {
  constructor(
    message: string,
    readonly status = 503,
  ) {
    super(message);
    this.name = "VrikaAiConfigurationError";
  }
}

const managedModelSchema = z.object({
  llm: z.object({
    provider: z.enum([
      "openai",
      "openrouter",
      "openai_compatible",
      "custom",
      "ollama",
    ]),
    model: z.string().trim().min(1),
    api_key: z.string().trim().default(""),
    base_url: z.string().trim().default(""),
  }),
});

/** Resolve credentials server-side without granting access to tenant settings. */
export async function fetchVrikaServerLlmConfig(): Promise<{
  apiKey: string;
  model: string;
  provider: LighthouseProvider;
  baseUrl: string | undefined;
}> {
  try {
    const session = await auth();
    if (!session?.accessToken) {
      throw new VrikaAiConfigurationError(
        "Sign in to use Cloud Security AI.",
        401,
      );
    }
    // Validate the token and current project bindings before trusting its tenant.
    const access = await fetch(`${apiBaseUrl}/users/me`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    if (access.status === 401 || access.status === 403) {
      throw new VrikaAiConfigurationError(
        "Cloud Security access is unavailable for this session. Refresh your session or contact your administrator.",
        access.status,
      );
    }
    if (!access.ok) {
      throw new VrikaAiConfigurationError(
        "Cloud Security access could not be verified. Please try again.",
      );
    }
    const claims = jwtDecode<{ tenant_id?: string }>(session.accessToken);
    if (!claims.tenant_id) {
      throw new VrikaAiConfigurationError(
        "Cloud Security session has no tenant.",
        401,
      );
    }

    const secret =
      process.env.VRIKA_INTERNAL_CONFIG_SECRET?.trim() ||
      process.env.VRIKA_BRIDGE_SECRET?.trim();
    if (!secret) {
      throw new VrikaAiConfigurationError(
        "Cloud Security AI connection is not configured. Contact your administrator.",
      );
    }
    const serverUrl = (
      process.env.VRIKA_SERVER_API_URL?.trim() || "http://vrika-server-api:8000"
    ).replace(/\/+$/, "");
    const res = await fetch(
      `${serverUrl}/internal/org-config?prowler_tenant_id=${encodeURIComponent(claims.tenant_id)}`,
      {
        headers: { "X-Vrika-Internal-Secret": secret },
        cache: "no-store",
        signal: AbortSignal.timeout(10000),
      },
    );
    if (!res.ok) {
      throw new VrikaAiConfigurationError(
        "Cloud Security AI configuration could not be loaded. Please try again.",
      );
    }
    const parsed = managedModelSchema.safeParse(await res.json());
    if (!parsed.success) {
      throw new VrikaAiConfigurationError(
        "Cloud Security AI is not configured for your organization. Contact your administrator.",
      );
    }
    const data = parsed.data.llm;
    const isLocalCustom =
      data.provider === "custom" || data.provider === "ollama";
    if (
      (!data.api_key && !isLocalCustom) ||
      (isLocalCustom && !data.base_url)
    ) {
      throw new VrikaAiConfigurationError(
        "Cloud Security AI is not configured for your organization. Contact your administrator.",
      );
    }
    const apiKey = data.api_key || "local";
    const baseUrl =
      data.base_url ||
      (data.provider === "openrouter" ? OPENROUTER_BASE_URL : undefined);
    const provider = normalizeLighthouseProvider(
      data.provider,
      data.provider === "openrouter",
      Boolean(baseUrl),
    );
    const model =
      provider === "openai" ? data.model.replace(/^openai\//, "") : data.model;

    return { apiKey, model, provider, baseUrl };
  } catch (error) {
    if (error instanceof VrikaAiConfigurationError) {
      console.error("[Vrika embed]", error.message);
      throw error;
    }
    console.error(
      "[Vrika embed] Model configuration request failed",
      error instanceof Error ? error.name : "Unknown error",
    );
    throw new VrikaAiConfigurationError(
      "Cloud Security AI configuration could not be loaded. Please try again.",
    );
  }
}
