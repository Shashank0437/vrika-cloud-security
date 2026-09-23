import type { LighthouseV2ToolCallContent } from "@/app/(prowler)/lighthouse/_types";

export { formatAiToolName as formatToolName } from "@/lib/branding";

// Reads the snake_case TOOL_CALL blob the backend persists and normalizes it to
// the camelCase UI shape. Returns null when `content` isn't a tool-call object.
export function getToolCallContent(
  content: unknown,
): LighthouseV2ToolCallContent | null {
  if (typeof content !== "object" || content === null) {
    return null;
  }
  const record = content as Record<string, unknown>;
  if (typeof record.tool_name !== "string") {
    return null;
  }
  return {
    toolCallId:
      typeof record.tool_call_id === "string" ? record.tool_call_id : "",
    toolName: record.tool_name,
    arguments: record.arguments ?? null,
    result: record.result ?? null,
    outcome: typeof record.outcome === "string" ? record.outcome : null,
  };
}

// A tool call succeeded when its outcome is absent or the literal "success";
// any other outcome is an error surfaced to the user.
export function isToolCallError(outcome: string | null): boolean {
  return outcome !== null && outcome.toLowerCase() !== "success";
}
