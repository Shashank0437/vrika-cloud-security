import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ProwlerExtended, ProwlerShort } from "./ProwlerIcons";

describe("Vrika logo compatibility exports", () => {
  it("renders Vrika assets for both legacy icon exports", () => {
    const { container } = render(
      <>
        <ProwlerShort />
        <ProwlerExtended />
      </>,
    );
    expect(screen.getAllByRole("img", { name: "Vrika" })).toHaveLength(2);
    const sources = Array.from(container.querySelectorAll("image"), (image) =>
      image.getAttribute("href"),
    );
    expect(sources.every((source) => source?.includes("/vrika-"))).toBe(true);
    expect(container.querySelector("path")).toBeNull();
  });
});
