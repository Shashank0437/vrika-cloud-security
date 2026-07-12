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

/** Product name shown in page titles and empty states. */
export function getEmbedAppName(): string {
  return isVrikaEmbedMode() ? "Cloud Security" : "Prowler";
}

/** ThreatScore label without vendor prefix in embed mode. */
export function getThreatScoreLabel(): string {
  return isVrikaEmbedMode() ? "ThreatScore" : "Prowler ThreatScore";
}

/** Upsell copy for Cloud-only features — no vendor name in embed mode. */
export function getCloudOnlyLabel(): string {
  return isVrikaEmbedMode()
    ? "Not available in this plan"
    : "Available in Prowler Cloud";
}

/** Hide Cloud upsell badges entirely in Vrika embed. */
export function shouldShowCloudUpsellBadge(): boolean {
  return !isVrikaEmbedMode();
}
