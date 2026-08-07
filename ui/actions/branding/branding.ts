"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import { UploadLogoPayload } from "@/types/branding";

const BRANDING_REVALIDATE_PATH = "/profile";

/**
 * Fetch the current tenant's report branding (custom logo metadata + preview).
 */
export const getTenantBranding = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/tenant-branding`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Upload or replace the tenant's custom report logo.
 * The image must be a base64-encoded PNG or JPEG (bare base64 or data URI).
 */
export const uploadTenantLogo = async (payload: UploadLogoPayload) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/tenant-branding`);

  try {
    const body = {
      data: {
        type: "tenant-branding",
        attributes: payload,
      },
    };

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });

    return handleApiResponse(response, BRANDING_REVALIDATE_PATH);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Remove the tenant's custom report logo, reverting reports to the default logo.
 */
export const deleteTenantLogo = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/tenant-branding`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (response.status === 204) {
      return { success: "Logo removed" };
    }

    return handleApiResponse(response, BRANDING_REVALIDATE_PATH);
  } catch (error) {
    return handleApiError(error);
  }
};
