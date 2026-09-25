import { z } from "zod";

import {
  FINDING_TRIAGE_STATUS,
  type TrackedFinding,
} from "@/types/findings-triage";

const trackedFindingSchema: z.ZodType<TrackedFinding> = z.object({
  id: z.string(),
  attributes: z.object({
    finding_uid: z.string(),
    provider_id: z.string(),
    provider_alias: z.string().nullable(),
    provider_type: z.string(),
    status: z.enum(FINDING_TRIAGE_STATUS),
    resolution_reason: z.string(),
    observation: z.string(),
    observation_detail: z.string(),
    snapshot: z.object({
      finding_id: z.string().optional(),
      scan_id: z.string().optional(),
      observed_at: z.string().optional(),
      provider_uid: z.string().optional(),
      check_id: z.string().optional(),
      title: z.string().optional(),
      severity: z.string().optional(),
      result: z.string().optional(),
      muted: z.boolean().optional(),
      resources: z
        .array(
          z.object({
            uid: z.string(),
            name: z.string(),
            region: z.string(),
            service: z.string(),
            type: z.string(),
          }),
        )
        .optional(),
    }),
    notes_count: z.number().int().nonnegative(),
    can_edit: z.boolean(),
    can_manage_exceptions: z.boolean(),
    updated_at: z.string(),
    verification_checked_at: z.string().nullable(),
    observation_scan_id: z.string().nullable(),
  }),
});

export const trackedFindingsResponseSchema = z.object({
  data: z.array(trackedFindingSchema),
  links: z.object({ next: z.string().nullable().optional() }).optional(),
});

export const trackedFindingsFiltersSchema = z.object({
  page: z.number().int().min(1).max(1_000_000).default(1),
  status: z.enum(FINDING_TRIAGE_STATUS).optional(),
  search: z.string().trim().max(200).default(""),
  providerId: z.uuid().optional(),
});

export const removalConfirmationSchema = z.object({
  triageId: z.uuid(),
  findingId: z.uuid(),
  observationScanId: z.uuid(),
  previousStatus: z.enum(FINDING_TRIAGE_STATUS),
  evidence: z.string().trim().min(3).max(500),
  confirmRemoved: z.literal(true),
});
