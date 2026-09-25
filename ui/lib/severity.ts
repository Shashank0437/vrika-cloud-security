import { SEVERITY_LEVELS, type SeverityLevel } from "@/types/severities";

export function normalizeSeverity(value: unknown): SeverityLevel {
  const raw = Array.isArray(value) ? value[0] : value;
  const normalized = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (normalized === "info") return "informational";
  return (
    SEVERITY_LEVELS.find((severity) => severity === normalized) ?? "unknown"
  );
}
