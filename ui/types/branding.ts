export interface TenantBrandingAttributes {
  has_custom_logo: boolean;
  logo_content_type: string;
  logo_filename: string;
  logo: string | null;
  inserted_at: string;
  updated_at: string;
  url: string;
}

export interface TenantBrandingData {
  type: "tenant-branding";
  id: string;
  attributes: TenantBrandingAttributes;
}

export interface TenantBrandingResponse {
  data: TenantBrandingData;
}

export interface UploadLogoPayload {
  logo_base64: string;
  logo_content_type: string;
  logo_filename: string;
}
