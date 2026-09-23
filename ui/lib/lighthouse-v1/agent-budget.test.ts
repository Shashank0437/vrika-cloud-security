import { AIMessage, HumanMessage } from "@langchain/core/messages";
import { tool } from "@langchain/core/tools";
import { FakeStreamingChatModel } from "@langchain/core/utils/testing";
import { createAgent, createMiddleware } from "langchain";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  createAgentBudget,
  MAX_TOOL_ROUNDS,
  TOOL_BUDGET_ERROR,
} from "./agent-budget";

function setup(rounds: number, bounded = true) {
  const execute = vi.fn(async () => "No matching admin users in this result");
  const availableTools = vi.fn();
  const model = new FakeStreamingChatModel({
    responses: [
      ...Array.from(
        { length: rounds },
        (_, index) =>
          new AIMessage({
            content: "",
            tool_calls: [{ id: `call-${index}`, name: "lookup", args: {} }],
          }),
      ),
      new AIMessage(
        "I could not confirm full administrator access from the available results.",
      ),
    ],
  });
  let nextResponse = 0;
  vi.spyOn(model, "bindTools").mockReturnValue(model);
  vi.spyOn(model, "_generate").mockImplementation(async () => {
    const template = model.responses[nextResponse++ % model.responses.length];
    if (!AIMessage.isInstance(template))
      throw new Error("Expected an AI fixture");
    const message = new AIMessage({
      content: template.content,
      tool_calls: template.tool_calls?.map((call) => ({
        ...call,
        id: `${call.id}-${nextResponse}`,
      })),
    });
    return { generations: [{ text: "", message }] };
  });
  const observer = createMiddleware({
    name: "ObserveModelTools",
    wrapModelCall: (request, handler) => {
      availableTools(request.tools.length);
      return handler(request);
    },
  });
  const agent = createAgent({
    model,
    tools: [
      tool(execute, {
        name: "lookup",
        description: "Read IAM data",
        schema: z.object({}),
      }),
    ],
    middleware: bounded
      ? ([createAgentBudget(), observer] as const)
      : ([observer] as const),
  });
  return { agent, execute, availableTools };
}

const prompt = new HumanMessage(
  "List my highest privileged AWS IAM users with full admin access",
);

describe("Lighthouse tool budget", () => {
  it("reproduces the original 25-step failure without the guard", async () => {
    const { agent } = setup(30, false);
    await expect(agent.invoke({ messages: [prompt] })).rejects.toThrow(
      "Recursion limit of 25",
    );
  });

  it("preserves a normal answer", async () => {
    const { agent, execute } = setup(2);
    const result = await agent.invoke({ messages: [prompt] });
    expect(execute).toHaveBeenCalledTimes(2);
    expect(result.messages.at(-1)?.content).toContain("could not confirm");
  });

  it("allows a final answer before the default graph limit", async () => {
    const { agent, execute, availableTools } = setup(MAX_TOOL_ROUNDS);
    const result = await agent.invoke({ messages: [prompt] });
    expect(execute).toHaveBeenCalledTimes(MAX_TOOL_ROUNDS);
    expect(result.messages.at(-1)?.content).toContain("could not confirm");
    expect(availableTools.mock.calls.map(([count]) => count)).toEqual([
      ...Array(MAX_TOOL_ROUNDS).fill(1),
      0,
    ]);
  });

  it("stops a model that ignores the final-answer instruction without executing more tools", async () => {
    const { agent, execute } = setup(30);
    await expect(agent.invoke({ messages: [prompt] })).rejects.toThrow(
      TOOL_BUDGET_ERROR,
    );
    expect(execute).toHaveBeenCalledTimes(MAX_TOOL_ROUNDS);
  });

  it("does not count earlier conversation turns against a new question", async () => {
    const { agent, execute } = setup(2);
    const first = await agent.invoke({ messages: [prompt] });
    const result = await agent.invoke({
      messages: [
        ...first.messages,
        new HumanMessage("Check another AWS account"),
      ],
    });
    expect(result.messages.at(-1)?.content).toContain("could not confirm");
    expect(execute).toHaveBeenCalledTimes(4);
  });
});
