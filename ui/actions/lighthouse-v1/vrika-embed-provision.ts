"use server";

import {
  createLighthouseProvider,
  getLighthouseProviderByType,
  getTenantConfig,
  isLighthouseConfigured,
  refreshProviderModels,
  testProviderConnection,
  updateTenantConfig,
} from "@/actions/lighthouse-v1/lighthouse";
import { getTask } from "@/actions/task/tasks";
import { checkTaskStatus } from "@/lib/helper";
import { isVrikaEmbedMode } from "@/lib/vrika-embed";
import type { LighthouseProvider } from "@/types/lighthouse-v1";

function readEmbedLighthouseEnv() {
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

  const provider = (process.env.VRIKA_LIGHTHOUSE_PROVIDER?.trim() ||
    process.env.VRIKA_LLM_PROVIDER?.trim()?.replace(
      /^openai$/,
      "openai_compatible",
    ) ||
    (usingOpenRouter || baseUrl
      ? "openai_compatible"
      : "openai")) as LighthouseProvider;

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

async function waitForTask(taskId: string, label: string): Promise<void> {
  const status = await checkTaskStatus(taskId, 40, 2000);
  if (!status.completed) {
    throw new Error(status.error || `${label} failed`);
  }
  const task = await getTask(taskId);
  const taskError = task.data?.attributes?.result?.error;
  if (taskError) {
    throw new Error(String(taskError));
  }
}

async function ensureProviderActive(
  providerType: LighthouseProvider,
  apiKey: string,
  baseUrl?: string,
): Promise<string> {
  const existing = await getLighthouseProviderByType(providerType);
  let providerId = existing.data?.id ? String(existing.data.id) : "";

  if (!providerId) {
    const created = await createLighthouseProvider(
      {
        provider_type: providerType,
        credentials: { api_key: apiKey },
        base_url: baseUrl,
      },
      { revalidate: false },
    );

    if (created.errors?.length) {
      const detail = created.errors[0]?.detail || "";
      if (!detail.toLowerCase().includes("already exists")) {
        throw new Error(detail || "Failed to create provider");
      }
      const retry = await getLighthouseProviderByType(providerType);
      providerId = retry.data?.id ? String(retry.data.id) : "";
      if (!providerId) {
        throw new Error("Lighthouse provider exists but could not be loaded");
      }
    } else {
      providerId = created.data?.id ? String(created.data.id) : "";
      if (!providerId) {
        throw new Error("Lighthouse provider create returned no id");
      }
    }
  }

  const connection = await testProviderConnection(providerId);
  if (connection.errors?.length) {
    throw new Error(
      connection.errors[0]?.detail || "Failed to start connection test",
    );
  }
  if (connection.data?.id) {
    await waitForTask(String(connection.data.id), "Connection test");
  }

  const refresh = await refreshProviderModels(String(providerId));
  if (refresh.errors?.length) {
    throw new Error(refresh.errors[0]?.detail || "Failed to refresh models");
  }
  if (refresh.data?.id) {
    await waitForTask(String(refresh.data.id), "Model refresh");
  }

  return providerId;
}

/**
 * Seed Lighthouse tenant LLM config from Vrika platform env (embed mode only).
 * Provider/model UI stays hidden; credentials never enter the browser.
 */
export async function ensureVrikaEmbedLighthouseConfig(): Promise<boolean> {
  if (!isVrikaEmbedMode()) {
    return false;
  }

  if (await isLighthouseConfigured()) {
    return true;
  }

  const { apiKey, model, provider, baseUrl } = readEmbedLighthouseEnv();
  if (!apiKey) {
    console.error(
      "[Vrika embed] Lighthouse not configured: set VRIKA_LLM_API_KEY (or VRIKA_LIGHTHOUSE_OPENAI_API_KEY)",
    );
    return false;
  }

  try {
    await ensureProviderActive(provider, apiKey, baseUrl);

    const tenantConfig = await getTenantConfig();
    const currentDefaults =
      tenantConfig?.data?.attributes?.default_models ?? {};
    const currentProvider =
      tenantConfig?.data?.attributes?.default_provider ?? provider;

    if (
      currentProvider === provider &&
      currentDefaults[provider] === model &&
      tenantConfig?.data
    ) {
      return true;
    }

    const updated = await updateTenantConfig(
      {
        default_provider: provider,
        default_models: { ...currentDefaults, [provider]: model },
      },
      { revalidate: false },
    );

    if (updated.errors?.length) {
      throw new Error(
        updated.errors[0]?.detail || "Failed to save tenant config",
      );
    }

    return await isLighthouseConfigured();
  } catch (error) {
    console.error("[Vrika embed] Lighthouse auto-provision failed:", error);
    return false;
  }
}
