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

export function readEmbedLighthouseEnv() {
  const apiKey =
    process.env.VRIKA_LLM_API_KEY?.trim() ||
    process.env.VRIKA_LIGHTHOUSE_OPENAI_API_KEY?.trim() ||
    process.env.OPENAI_API_KEY?.trim() ||
    "";

  const baseUrl =
    process.env.VRIKA_LLM_URL?.trim() ||
    process.env.VRIKA_LIGHTHOUSE_BASE_URL?.trim() ||
    undefined;

  const usingOpenRouter =
    apiKey.startsWith("sk-or-") || baseUrl?.includes("openrouter.ai") === true;

  const explicitProvider =
    process.env.VRIKA_LIGHTHOUSE_PROVIDER?.trim() ||
    process.env.VRIKA_LLM_PROVIDER?.trim();

  const provider = normalizeLighthouseProvider(
    explicitProvider,
    usingOpenRouter,
    Boolean(baseUrl),
  );

  const rawModel =
    process.env.VRIKA_LLM_MODEL?.trim() ||
    process.env.VRIKA_LIGHTHOUSE_MODEL?.trim() ||
    "openai/gpt-4.1-mini";

  const model =
    provider === "openai" && rawModel.startsWith("openai/")
      ? rawModel.replace(/^openai\//, "")
      : rawModel;

  const resolvedBaseUrl =
    baseUrl ||
    (provider === "openai_compatible" && usingOpenRouter
      ? "https://openrouter.ai/api/v1"
      : undefined);

  return { apiKey, model, provider, baseUrl: resolvedBaseUrl };
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

/**
 * Dynamically query vrika-server's central settings store for the active organization's LLM credentials.
 */
export async function fetchVrikaServerLlmConfig(): Promise<{
  apiKey: string;
  model: string;
  provider: LighthouseProvider;
  baseUrl: string | undefined;
} | null> {
  const secret = process.env.VRIKA_BRIDGE_SECRET?.trim() || "";
  const serverUrl = process.env.VRIKA_SERVER_API_URL?.trim() || "http://vrika-server-api:8000";

  if (!secret) return null;

  try {
    const res = await fetch(`${serverUrl}/org/settings/llm/internal-resolve?secret=${encodeURIComponent(secret)}`, {
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data.configured) return null;
    const isLocalCustom = data.provider === "custom" || data.provider === "ollama" || Boolean(data.base_url);
    if (!data.api_key && !isLocalCustom) return null;

    const apiKey = String(data.api_key || (isLocalCustom ? "local" : "")).trim();
    const baseUrl = data.base_url?.trim() || (data.provider === "openrouter" ? "https://openrouter.ai/api/v1" : undefined);
    const provider = normalizeLighthouseProvider(data.provider, data.provider === "openrouter", Boolean(baseUrl));
    const model = data.model || (isLocalCustom ? "local-model" : "openai/gpt-4.1-mini");

    return { apiKey, model, provider, baseUrl };
  } catch (err) {
    console.warn("[Vrika embed] Failed to resolve dynamic LLM from vrika-server:", err);
    return null;
  }
}
