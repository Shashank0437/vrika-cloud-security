import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { adaptToSankeyData } from "@/actions/overview/providers/sankey.adapter";
import { SeverityBadge } from "@/components/shadcn/table/severity-badge";
import { SEVERITY_FILTER_MAP, SEVERITY_LINE_CONFIGS } from "@/types/severities";

import { normalizeSeverity } from "./severity";

describe("Unknown / Unrated severity", () => {
  it.each(["UNKNOWN", "unrated", "future-label", "", null, undefined, 12])(
    "does not invent a rating for %s",
    (value) => expect(normalizeSeverity(value)).toBe("unknown"),
  );

  it.each([
    [" HIGH ", "high"],
    ["INFO", "informational"],
    ["critical", "critical"],
  ])("preserves recognized rating %s", (input, expected) => {
    expect(normalizeSeverity(input)).toBe(expected);
  });

  it("shows the explicit label, trend series, and filter value", () => {
    render(<SeverityBadge severity="unknown" />);
    expect(screen.getByText("Unknown / Unrated")).toBeInTheDocument();
    expect(SEVERITY_FILTER_MAP["Unknown / Unrated"]).toBe("unknown");
    expect(
      SEVERITY_LINE_CONFIGS.some((line) => line.dataKey === "unknown"),
    ).toBe(true);
  });

  it("does not treat a provider with only unknown failures as clean", () => {
    const data = adaptToSankeyData({
      iac: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
        unknown: 11,
      },
    });
    expect(data.zeroDataProviders).toEqual([]);
    expect(data.links).toHaveLength(1);
    expect(data.links[0].value).toBe(11);
    expect(data.nodes[data.links[0].target].name).toBe("Unknown / Unrated");
  });
});
