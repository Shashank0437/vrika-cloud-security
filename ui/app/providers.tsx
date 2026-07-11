"use client";

import { SessionProvider } from "next-auth/react";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import { ThemeProviderProps } from "next-themes/dist/types";
import { ReactNode } from "react";

import { authApiBasePath } from "@/lib/base-path";

export interface ProvidersProps {
  children: ReactNode;
  themeProps?: ThemeProviderProps;
}

export function Providers({ children, themeProps }: ProvidersProps) {
  return (
    <SessionProvider basePath={authApiBasePath()}>
      <NextThemesProvider {...themeProps}>{children}</NextThemesProvider>
    </SessionProvider>
  );
}
