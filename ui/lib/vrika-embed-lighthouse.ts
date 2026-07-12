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
