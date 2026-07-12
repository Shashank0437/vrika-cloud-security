/** True when Prowler UI is built for embedding inside Vrika (white-label chrome). */
export function isVrikaEmbedMode(): boolean {
  return process.env.NEXT_PUBLIC_VRIKA_EMBED_MODE === "true";
}

/** Nav labels hidden in Vrika embed mode. */
export const VRIKA_EMBED_HIDDEN_MENU_LABELS = new Set([
  "Organization",
  "Support & Help",
  "Prowler Hub",
]);

/** Prowler routes blocked in Vrika embed (chat is allowed; settings are not). */
export const VRIKA_EMBED_BLOCKED_ROUTE_PREFIXES = [
  "/profile",
  "/lighthouse/settings",
  "/users",
  "/invitations",
  "/roles",
] as const;

export function isVrikaEmbedBlockedRoute(pathname: string): boolean {
  return VRIKA_EMBED_BLOCKED_ROUTE_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

/** AI assistant product name in page titles, nav, and CTAs. */
export function getVrikaAiLabel(): string {
  return isVrikaEmbedMode() ? "Vrika AI" : "Lighthouse AI";
}

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
