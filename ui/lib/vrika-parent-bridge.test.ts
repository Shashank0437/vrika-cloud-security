import { describe, expect, it } from "vitest";

import { normalizeBridgePath, toAppRouterPath } from "./vrika-parent-bridge";

describe("vrika-parent-bridge", () => {
  it("normalizes empty paths to overview", () => {
    expect(normalizeBridgePath("")).toBe("/");
    expect(normalizeBridgePath("/")).toBe("/");
  });

  it("preserves query strings for findings navigation", () => {
    expect(
      normalizeBridgePath(
        "/findings?filter[muted]=false&filter[status__in]=FAIL",
      ),
    ).toBe("/findings?filter[muted]=false&filter[status__in]=FAIL");
  });

  it("maps bridge paths to app router paths without base path prefix", () => {
    expect(toAppRouterPath("/compliance")).toBe("/compliance");
    expect(toAppRouterPath("/")).toBe("/");
  });
});
