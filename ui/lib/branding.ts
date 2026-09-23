/** Branding for display prose only, never API keys, resource IDs or commands. */
export function brandText(text: string): string {
  return text.replace(
    /https?:\/\/\S+|\bprowlerthreatscore\b|\bprowler\b/gi,
    (match) => {
      if (/^https?:\/\//i.test(match)) return match;
      return /^prowlerthreatscore$/i.test(match)
        ? "Vrika ThreatScore"
        : "Vrika";
    },
  );
}

interface MarkdownNode {
  type: string;
  value?: string;
  children?: MarkdownNode[];
}

/** Transform prose nodes, preserving code, link destinations and raw HTML. */
export function remarkVrikaBranding() {
  return (tree: MarkdownNode) => {
    function visit(node: MarkdownNode) {
      if (node.type === "text" && node.value)
        node.value = brandText(node.value);
      node.children?.forEach(visit);
    }
    visit(tree);
  };
}

export function formatAiToolName(toolName: string): string {
  const name = toolName.replace(/^prowler_(?:app_|hub_|docs_)?/, "");
  const words = name.replace(/_/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Tool";
}
