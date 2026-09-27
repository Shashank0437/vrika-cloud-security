import { render, screen } from "@testing-library/react";
import type { ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Chat } from "./chat";

const { sendMessage } = vi.hoisted(() => ({ sendMessage: vi.fn() }));
vi.mock("@ai-sdk/react", () => ({
  useChat: () => ({
    messages: [],
    status: "ready",
    sendMessage,
    setMessages: vi.fn(),
    regenerate: vi.fn(),
    stop: vi.fn(),
  }),
}));
vi.mock("@/actions/lighthouse-v1/lighthouse", () => ({
  getLighthouseModelIds: vi.fn(),
}));
vi.mock("@/lib/vrika-embed", () => ({
  isVrikaEmbedMode: () => true,
  getVrikaAiLabel: () => "Vrika AI",
}));
vi.mock("@/components/lighthouse-v1/message-item", () => ({
  MessageItem: () => null,
}));
vi.mock("@/components/shadcn", async () => {
  const cards = await import("@/components/shadcn/card/card");
  return {
    ...cards,
    Button: ({ children, ...props }: ComponentProps<"button">) => (
      <button {...props}>{children}</button>
    ),
    Combobox: () => null,
    useToast: () => ({ toast: vi.fn() }),
  };
});

describe("embedded chat unavailable state", () => {
  beforeEach(() => {
    sendMessage.mockClear();
  });

  it("has a responsive width and displays the specific server error", () => {
    render(
      <Chat
        hasConfig={false}
        providers={[]}
        unavailableReason="Project access could not be verified."
      />,
    );
    const card = screen
      .getByText("AI assistant unavailable")
      .closest("[data-slot=card]");
    expect(card).toHaveClass("w-full", "max-w-md");
    expect(card?.parentElement).toHaveClass("p-4");
    expect(
      screen.getByText("Project access could not be verified."),
    ).toBeVisible();
    expect(screen.queryByText("Configure LLM")).not.toBeInTheDocument();
  });

  it("does not submit a finding prompt while AI is unavailable", () => {
    render(
      <Chat
        hasConfig={false}
        providers={[]}
        initialPrompt="Analyze this finding"
      />,
    );
    expect(sendMessage).not.toHaveBeenCalled();
    expect(
      screen
        .getAllByRole("button", { name: /^Send message:/ })
        .every((button) => button.hasAttribute("disabled")),
    ).toBe(true);
  });

  it("sends the initial prompt when the managed model is available", () => {
    render(
      <Chat
        hasConfig={true}
        providers={[]}
        initialPrompt="Analyze this finding"
        defaultProviderId="openai_compatible"
        defaultModelId="organization/model"
      />,
    );
    expect(sendMessage).toHaveBeenCalledWith({ text: "Analyze this finding" });
    expect(
      screen.queryByText("AI assistant unavailable"),
    ).not.toBeInTheDocument();
  });
});
