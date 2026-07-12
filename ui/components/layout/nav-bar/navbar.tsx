import { ReactNode, Suspense } from "react";

import { FeedsServer } from "@/components/feeds";
import { isVrikaEmbedMode } from "@/lib/vrika-embed";

import {
  FeedsLoadingFallback,
  NavbarClient,
  type OnboardingActionConfig,
} from "./navbar-client";

export type { OnboardingActionConfig };

interface NavbarProps {
  title: string;
  icon?: string | ReactNode;
  onboardingAction?: OnboardingActionConfig;
}

export function Navbar({ title, icon, onboardingAction }: NavbarProps) {
  if (isVrikaEmbedMode()) {
    return null;
  }

  return (
    <NavbarClient
      title={title}
      icon={icon}
      onboardingAction={onboardingAction}
      feedsSlot={
        isVrikaEmbedMode() ? undefined : (
          <Suspense key="feeds" fallback={<FeedsLoadingFallback />}>
            <FeedsServer limit={15} />
          </Suspense>
        )
      }
    />
  );
}
