"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo } from "react";

import { isVrikaEmbedMode } from "@/lib/vrika-embed";
import {
  isAllowedBridgeOrigin,
  normalizeBridgePath,
  postPathnameToParent,
  toAppRouterPath,
  VRIKA_NAVIGATE_MESSAGE,
  type VrikaNavigateMessage,
} from "@/lib/vrika-parent-bridge";

export function VrikaParentBridge() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const router = useRouter();

  const searchString = searchParams.toString();
  const currentBridgePath = useMemo(
    () =>
      normalizeBridgePath(
        `${pathname}${searchString ? `?${searchString}` : ""}`,
      ),
    [pathname, searchString],
  );

  useEffect(() => {
    if (!isVrikaEmbedMode()) return;

    const onMessage = (event: MessageEvent) => {
      if (!isAllowedBridgeOrigin(event.origin)) return;
      const data = event.data as Partial<VrikaNavigateMessage> | null;
      if (
        data?.type !== VRIKA_NAVIGATE_MESSAGE ||
        typeof data.path !== "string"
      ) {
        return;
      }

      const target = normalizeBridgePath(toAppRouterPath(data.path));
      if (target !== currentBridgePath) {
        router.push(toAppRouterPath(data.path));
      }
    };

    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [currentBridgePath, router]);

  useEffect(() => {
    if (!isVrikaEmbedMode()) return;
    postPathnameToParent(pathname, searchString ? `?${searchString}` : "");
  }, [pathname, searchString]);

  return null;
}

export { normalizeBridgePath };
