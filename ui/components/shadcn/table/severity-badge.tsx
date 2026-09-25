import { normalizeSeverity } from "@/lib/severity";
import { cn } from "@/lib/utils";

export const SeverityValues = {
  INFORMATIONAL: "informational",
  UNKNOWN: "unknown",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type Severity = (typeof SeverityValues)[keyof typeof SeverityValues];

const SEVERITY_CHIP_COLORS = {
  critical: "bg-bg-data-critical",
  high: "bg-bg-data-high",
  medium: "bg-bg-data-medium",
  low: "bg-bg-data-low",
  informational: "bg-bg-data-info",
  unknown: "bg-bg-data-muted",
} as const;

const SEVERITY_DISPLAY_NAMES = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
  unknown: "Unknown / Unrated",
} as const;

interface SeverityBadgeProps {
  severity: Severity;
}

export const SeverityBadge = ({ severity }: SeverityBadgeProps) => {
  const normalized = normalizeSeverity(severity);
  const chipColor = SEVERITY_CHIP_COLORS[normalized];
  const displayName = SEVERITY_DISPLAY_NAMES[normalized];

  return (
    <div className="flex items-center gap-1">
      <div className={cn("size-3 rounded", chipColor)} />
      <span className="text-text-neutral-primary text-sm capitalize">
        {displayName}
      </span>
    </div>
  );
};
