/** True when Prowler UI is built for embedding inside Vrika (white-label chrome). */
export function isVrikaEmbedMode(): boolean {
  return process.env.NEXT_PUBLIC_VRIKA_EMBED_MODE === "true";
}

/** Nav labels hidden in Vrika embed mode. */
export const VRIKA_EMBED_HIDDEN_MENU_LABELS = new Set([
  "Organization",
  "Support & Help",
  "Prowler Hub",
  "Lighthouse AI",
]);
