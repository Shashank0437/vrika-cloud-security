import { ReactNode } from "react";

import {
  Navbar,
  type OnboardingActionConfig,
} from "@/components/layout/nav-bar/navbar";
import { cn } from "@/lib/utils";
import { isVrikaEmbedMode } from "@/lib/vrika-embed";

interface ContentLayoutProps {
  title: string;
  icon?: string | ReactNode;
  onboardingAction?: OnboardingActionConfig;
  children: React.ReactNode;
}

export function ContentLayout({
  title,
  icon,
  onboardingAction,
  children,
}: ContentLayoutProps) {
  const embedMode = isVrikaEmbedMode();

  return (
    <>
      <Navbar title={title} icon={icon} onboardingAction={onboardingAction} />
      <div className={cn("py-4 pr-6", embedMode && "py-0 pr-0")}>
        {children}
      </div>
    </>
  );
}
