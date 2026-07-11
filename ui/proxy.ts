import { NextResponse } from "next/server";
import type { NextAuthRequest } from "next-auth";

import { auth } from "@/auth.config";
import { withAppPath, stripAppPath } from "@/lib/base-path";

const publicRoutes = [
  "/sign-in",
  "/sign-up",
  "/invitation/accept",
  // In Cloud uncomment the following lines:
  // "/reset-password",
  // "/email-verification",
  // "/set-password",
];

const isPublicRoute = (pathname: string): boolean => {
  return publicRoutes.some((route) => pathname.startsWith(route));
};

// NextAuth's auth() wrapper - renamed from middleware to proxy
export default auth((req: NextAuthRequest) => {
  const pathname = stripAppPath(req.nextUrl.pathname);

  const user = req.auth?.user;
  const sessionError = req.auth?.error;

  // If there's a session error (e.g., RefreshAccessTokenError), redirect to login with error info
  if (sessionError && !isPublicRoute(pathname)) {
    const signInUrl = new URL(withAppPath("/sign-in"), req.nextUrl.origin);
    signInUrl.searchParams.set("error", sessionError);
    signInUrl.searchParams.set(
      "callbackUrl",
      withAppPath(pathname) + req.nextUrl.search,
    );
    return NextResponse.redirect(signInUrl);
  }

  if (!user && !isPublicRoute(pathname)) {
    const signInUrl = new URL(withAppPath("/sign-in"), req.nextUrl.origin);
    signInUrl.searchParams.set(
      "callbackUrl",
      withAppPath(pathname) + req.nextUrl.search,
    );
    return NextResponse.redirect(signInUrl);
  }

  if (user?.permissions) {
    const permissions = user.permissions;

    if (pathname.startsWith("/billing") && !permissions.manage_billing) {
      return NextResponse.redirect(
        new URL(withAppPath("/profile"), req.nextUrl.origin),
      );
    }

    if (
      pathname.startsWith("/integrations") &&
      !permissions.manage_integrations
    ) {
      return NextResponse.redirect(
        new URL(withAppPath("/profile"), req.nextUrl.origin),
      );
    }
  }

  return NextResponse.next();
});

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - *.png, *.jpg, *.jpeg, *.svg, *.ico (image files)
     */
    "/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|svg|ico|css|js)$).*)",
  ],
};
