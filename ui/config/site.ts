import { isVrikaEmbedMode } from "@/lib/vrika-embed";

export type SiteConfig = typeof siteConfig;

const isCloudEnv = process.env.NEXT_PUBLIC_IS_CLOUD_ENV === "true";

export const siteConfig = {
  name: isVrikaEmbedMode()
    ? "Cloud Security"
    : isCloudEnv
      ? "Vrika Cloud"
      : "Vrika",
  description:
    "Vrika Cloud Security helps teams assess cloud security, investigate findings and attack paths, and track compliance across their connected cloud environments.",
};
