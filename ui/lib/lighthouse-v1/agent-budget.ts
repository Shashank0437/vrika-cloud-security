import { AIMessage, HumanMessage } from "@langchain/core/messages";
import { createMiddleware } from "langchain";

// Each tool round consumes model + tool graph steps. Reserve a final model
// response within LangGraph's default 25-step limit, without extra tool calls.
export const MAX_TOOL_ROUNDS = 8;
export const TOOL_BUDGET_ERROR =
  "The AI could not finish this analysis within its tool limit. Please narrow the question to one account or try again.";

export function createAgentBudget() {
  return createMiddleware({
    name: "LighthouseToolBudget",
    wrapModelCall: async (request, handler) => {
      const lastUser = request.messages.findLastIndex(HumanMessage.isInstance);
      const rounds = request.messages
        .slice(lastUser + 1)
        .filter(
          (message) =>
            AIMessage.isInstance(message) && message.tool_calls?.length,
        ).length;
      if (rounds < MAX_TOOL_ROUNDS) return handler(request);

      const response = await handler({
        ...request,
        tools: [],
        systemMessage: request.systemMessage.concat(
          "\nTool budget reached. Give a final answer using only evidence already retrieved. " +
            "Explicitly state any incomplete coverage, unavailable data, or tool errors. " +
            "Do not infer that no admin users exist from missing or failed results. " +
            "Do not call more tools; ask the user to narrow the scope if needed.",
        ),
      });
      if (response.tool_calls?.length) throw new Error(TOOL_BUDGET_ERROR);
      return response;
    },
  });
}
