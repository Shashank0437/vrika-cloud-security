import { getTenantBranding } from "@/actions/branding/branding";
import { TenantBrandingAttributes } from "@/types/branding";

import { ReportBrandingCardClient } from "./report-branding-card-client";

export const ReportBrandingCard = async () => {
  const response = await getTenantBranding();
  const branding: TenantBrandingAttributes | null =
    response?.data?.attributes ?? null;

  return <ReportBrandingCardClient branding={branding} />;
};
