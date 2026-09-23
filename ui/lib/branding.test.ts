import { describe, expect, it } from "vitest";

import { brandText, formatAiToolName, remarkVrikaBranding } from "./branding";

describe("Vrika presentation branding", () => {
  it("brands prose and framework display names without rewriting identifiers or URLs", () => {
    expect(brandText("Prowler Cloud / prowler / ProwlerThreatScore")).toBe(
      "Vrika Cloud / Vrika / Vrika ThreatScore",
    );
    expect(
      brandText(
        "prowler_app_list_scans ProwlerFinding prowler_threatscore_aws",
      ),
    ).toBe("prowler_app_list_scans ProwlerFinding prowler_threatscore_aws");
    expect(brandText("https://docs.prowler.com/Prowler")).toBe(
      "https://docs.prowler.com/Prowler",
    );
  });

  it("does not change Markdown code or actual link destinations", () => {
    const tree = {
      type: "root",
      children: [
        { type: "text", value: "Prowler findings" },
        { type: "inlineCode", value: "prowler aws" },
        { type: "code", value: "prowler aws --profile Prowler" },
        {
          type: "link",
          url: "https://docs.prowler.com",
          children: [{ type: "text", value: "Prowler docs" }],
        },
      ],
    };
    remarkVrikaBranding()(tree);
    expect(tree.children[0].value).toBe("Vrika findings");
    expect(tree.children[1].value).toBe("prowler aws");
    expect(tree.children[2].value).toBe("prowler aws --profile Prowler");
    expect(tree.children[3].url).toBe("https://docs.prowler.com");
    expect(tree.children[3].children?.[0].value).toBe("Vrika docs");
  });

  it.each(["prowler_app_list_scans", "prowler_list_scans"])(
    "humanizes tool progress without exposing the namespace: %s",
    (name) => expect(formatAiToolName(name)).toBe("List scans"),
  );
});
