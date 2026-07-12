import { stripAppPath } from "@/lib/base-path";

export const VRIKA_NAVIGATE_MESSAGE = "vrika:navigate" as const;
export const VRIKA_PATHNAME_MESSAGE = "vrika:pathname" as const;

export type VrikaNavigateMessage = {
  type: typeof VRIKA_NAVIGATE_MESSAGE;
  path: string;
};

export type VrikaPathnameMessage = {
  type: typeof VRIKA_PATHNAME_MESSAGE;
  path: string;
};

export function isAllowedBridgeOrigin(origin: string): boolean {
  if (typeof window === "undefined" || !origin) return false;
  try {
    return new URL(origin).hostname === window.location.hostname;
  } catch {
    return false;
  }
}

export function normalizeBridgePath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed || trimmed === "/") return "/";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return stripAppPath(withSlash.split("#")[0] ?? withSlash);
}

/** Path for `router.push` — must NOT include `NEXT_PUBLIC_BASE_PATH` (Next adds it). */
export function toAppRouterPath(path: string): string {
  return normalizeBridgePath(path);
}

export function postPathnameToParent(pathname: string, search = ""): void {
  if (typeof window === "undefined" || window.parent === window) return;

  const searchPart = search.startsWith("?")
    ? search
    : search
      ? `?${search}`
      : "";

  const message: VrikaPathnameMessage = {
    type: VRIKA_PATHNAME_MESSAGE,
    path: normalizeBridgePath(`${pathname}${searchPart}`),
  };

  window.parent.postMessage(message, window.location.origin);
}
