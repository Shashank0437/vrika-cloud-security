import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { MessageMarkdown } from "./message-markdown";

describe("AI response branding", () => {
  it("brands streamed-response prose without changing commands or documentation URLs", () => {
    render(
      <MessageMarkdown
        text={
          "Prowler analysis.\n\nRun `prowler aws`.\n\n[Prowler docs](https://docs.prowler.com/)"
        }
      />,
    );
    expect(screen.getByText("Vrika analysis.")).toBeInTheDocument();
    expect(screen.getByText("prowler aws").tagName).toBe("CODE");
    expect(screen.getByRole("link", { name: /Vrika docs/ })).toHaveAttribute(
      "href",
      "https://docs.prowler.com/",
    );
  });
});
