import { createAgent } from "langchain";

import {
  getProviderCredentials,
  getTenantConfig,
} from "@/actions/lighthouse-v1/lighthouse";
import { createAgentBudget } from "@/lib/lighthouse-v1/agent-budget";
import { TOOLS_UNAVAILABLE_MESSAGE } from "@/lib/lighthouse-v1/constants";
import type { ProviderType } from "@/lib/lighthouse-v1/llm-factory";
import { createLLM } from "@/lib/lighthouse-v1/llm-factory";
import {
  getMCPTools,
  initializeMCPClient,
  isMCPAvailable,
} from "@/lib/lighthouse-v1/mcp-client";
import { getAllSkillMetadata } from "@/lib/lighthouse-v1/skills/index";
import {
  generateSkillCatalog,
  generateUserDataSection,
  LIGHTHOUSE_SYSTEM_PROMPT_TEMPLATE,
} from "@/lib/lighthouse-v1/system-prompt";
import {
  getCanonicalToolName,
  isAllowedTool,
} from "@/lib/lighthouse-v1/tool-policy";
import { loadSkill } from "@/lib/lighthouse-v1/tools/load-skill";
import { describeTool, executeTool } from "@/lib/lighthouse-v1/tools/meta-tool";
import { getModelParams } from "@/lib/lighthouse-v1/utils";
import { isVrikaEmbedMode } from "@/lib/vrika-embed";
import {
  fetchVrikaServerLlmConfig,
  resolveOpenRouterLlmRouting,
} from "@/lib/vrika-embed-lighthouse";

export interface RuntimeConfig {
  model?: string;
  provider?: string;
  businessContext?: string;
  currentData?: string;
}

function readApiKey(
  credentials: Awaited<
    ReturnType<typeof getProviderCredentials>
  >["credentials"],
): string | undefined {
  return "api_key" in credentials ? credentials.api_key : undefined;
}

/**
 * Truncate description to specified length
 */
function truncateDescription(desc: string | undefined, maxLen: number): string {
  if (!desc) return "No description available";

  const cleaned = desc.replace(/\n/g, " ").replace(/\s+/g, " ").trim();

  if (cleaned.length <= maxLen) return cleaned;

  return cleaned.substring(0, maxLen) + "...";
}

/**
 * Generate dynamic tool listing from MCP tools.
 * Only includes tools that are explicitly whitelisted.
 */
function generateToolListing(): string {
  if (!isMCPAvailable()) {
    return TOOLS_UNAVAILABLE_MESSAGE;
  }

  const mcpTools = getMCPTools();

  if (mcpTools.length === 0) {
    return TOOLS_UNAVAILABLE_MESSAGE;
  }

  // Only include whitelisted tools
  const safeTools = mcpTools.filter((tool) => isAllowedTool(tool.name));

  let listing = "\n## Available Vrika Tools\n\n";
  listing += `${safeTools.length} tools loaded from Vrika MCP\n\n`;

  for (const tool of safeTools) {
    const desc = truncateDescription(tool.description, 150);
    listing += `- **${getCanonicalToolName(tool.name)}**: ${desc}\n`;
  }

  listing +=
    "\nUse describe_tool with exact tool name to see full schema and parameters.\n";

  return listing;
}

export async function initLighthouseWorkflow(runtimeConfig?: RuntimeConfig) {
  await initializeMCPClient();

  const toolListing = generateToolListing();

  let systemPrompt = LIGHTHOUSE_SYSTEM_PROMPT_TEMPLATE.replace(
    "{{TOOL_LISTING}}",
    toolListing,
  );

  // Generate and inject skill catalog
  const skillCatalog = generateSkillCatalog(getAllSkillMetadata());
  systemPrompt = systemPrompt.replace("{{SKILL_CATALOG}}", skillCatalog);

  // Add user-provided data section if available
  const userDataSection = generateUserDataSection(
    runtimeConfig?.businessContext,
    runtimeConfig?.currentData,
  );

  if (userDataSection) {
    systemPrompt += userDataSection;
  }

  let providerType: ProviderType;
  let modelId: string;
  let credentials: Awaited<
    ReturnType<typeof getProviderCredentials>
  >["credentials"];
  let baseUrl: string | undefined;
  if (isVrikaEmbedMode()) {
    const managed = await fetchVrikaServerLlmConfig();
    providerType = managed.provider;
    modelId = managed.model;
    credentials = { api_key: managed.apiKey };
    baseUrl = managed.baseUrl;
  } else {
    const tenantConfigResult = await getTenantConfig();
    const tenantConfig = tenantConfigResult?.data?.attributes;
    const defaultProvider = tenantConfig?.default_provider || "openai";
    const defaultModels = tenantConfig?.default_models || {};
    providerType = (runtimeConfig?.provider?.trim() ||
      defaultProvider) as ProviderType;
    modelId =
      runtimeConfig?.model?.trim() ||
      defaultModels[defaultProvider] ||
      "gpt-5.2";
    const providerConfig = await getProviderCredentials(providerType);
    credentials = providerConfig.credentials;
    baseUrl = providerConfig.base_url;
  }

  let effectiveKey = readApiKey(credentials);
  const isLocalCustom =
    providerType === "openai_compatible" || Boolean(baseUrl);
  if (!effectiveKey && isLocalCustom) {
    effectiveKey = "local";
    credentials = { api_key: "local" };
  }

  if (!effectiveKey) {
    throw new Error(
      "LLM provider is not configured. Please configure an active AI provider in Settings > LLM Configuration.",
    );
  }

  const routed = resolveOpenRouterLlmRouting(
    providerType,
    effectiveKey,
    baseUrl,
  );
  providerType = routed.provider as ProviderType;
  baseUrl = routed.baseUrl;

  // Get model params
  const modelParams = getModelParams({ model: modelId });

  // Initialize LLM
  const llm = createLLM({
    provider: providerType,
    model: modelId,
    credentials,
    baseUrl,
    streaming: true,
    tags: ["lighthouse-agent"],
    modelParams,
  });

  const agent = createAgent({
    model: llm,
    tools: [describeTool, executeTool, loadSkill],
    systemPrompt,
    middleware: [createAgentBudget()],
  });

  return agent;
}
