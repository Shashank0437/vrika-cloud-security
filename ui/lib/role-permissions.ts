import { permissionFormFields } from "@/lib";

const hiddenOutsideCloudFields = ["manage_billing", "manage_alerts"];

export const getVisiblePermissionFormFields = (isCloudEnvironment: boolean) =>
  permissionFormFields.filter(
    (permission) =>
      permission.field !== "unlimited_visibility" &&
      (!["manage_triage", "manage_triage_exceptions"].includes(
        permission.field,
      ) ||
        process.env.NEXT_PUBLIC_VRIKA_TRIAGE_ENABLED === "true") &&
      (!hiddenOutsideCloudFields.includes(permission.field) ||
        isCloudEnvironment),
  );

export const getUnlimitedVisibilityField = () =>
  permissionFormFields.find(({ field }) => field === "unlimited_visibility");
