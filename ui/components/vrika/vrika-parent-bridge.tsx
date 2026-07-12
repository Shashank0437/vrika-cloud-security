"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

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
  const router = useRouter();

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

      const target = toAppRouterPath(data.path);
      if (target !== pathname) {
        router.push(target);
      }
    };

    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [pathname, router]);

  useEffect(() => {
    if (!isVrikaEmbedMode()) return;
    postPathnameToParent(pathname);
  }, [pathname]);

  return null;
}

export { normalizeBridgePath };
