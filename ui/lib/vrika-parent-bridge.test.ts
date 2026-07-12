import { describe, expect, it, vi } from "vitest";

import {
  normalizeBridgePath,
  postPathnameToParent,
  toAppRouterPath,
} from "./vrika-parent-bridge";

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

  it("includes search params when posting pathname to parent", () => {
    const postMessage = vi.fn();
    Object.defineProperty(window, "parent", {
      configurable: true,
      value: { postMessage },
    });

    postPathnameToParent(
      "/findings",
      "?filter[muted]=false&filter[status__in]=FAIL",
    );

    expect(postMessage).toHaveBeenCalledWith(
      {
        type: "vrika:pathname",
        path: "/findings?filter[muted]=false&filter[status__in]=FAIL",
      },
      window.location.origin,
    );
  });

  it("maps bridge paths to app router paths without base path prefix", () => {
    expect(toAppRouterPath("/compliance")).toBe("/compliance");
    expect(toAppRouterPath("/")).toBe("/");
  });
});
