import { getThreatScoreLabel } from "@/lib/vrika-embed";

export const ThreatScoreLogo = () => (
  <span
    className="text-text-neutral-primary shrink-0 text-lg leading-none font-bold tracking-tight whitespace-nowrap"
    aria-label={getThreatScoreLabel()}
  >
    {getThreatScoreLabel()}
  </span>
);
