import { withAppPath } from "@/lib/base-path";
import type { IconSvgProps } from "@/types";

// Keep the existing component exports so callers and icon registries stay stable.
export const ProwlerExtended = ({
  size,
  width = 216,
  height = 66,
  ...props
}: IconSvgProps) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 1275 392"
    width={size || width}
    height={size || height}
    aria-label="Vrika"
    role="img"
    {...props}
  >
    <image
      className="dark:hidden"
      href={withAppPath("/vrika-wordmark.png")}
      width="1275"
      height="392"
    />
    <image
      className="hidden dark:block"
      href={withAppPath("/vrika-wordmark-dark.png")}
      width="1275"
      height="392"
    />
  </svg>
);

export const ProwlerShort = ({
  size,
  width = 30,
  height = 30,
  ...props
}: IconSvgProps) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 96 96"
    width={size || width}
    height={size || height}
    aria-label="Vrika"
    role="img"
    {...props}
  >
    <image href={withAppPath("/vrika-mark.png")} width="96" height="96" />
  </svg>
);
