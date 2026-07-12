"use server";

import { NextResponse } from "next/server";

import { signIn } from "@/auth.config";
import { getSafeCallbackPathFromValue } from "@/lib/auth-callback-url";
import { withAppPath, appBasePath } from "@/lib/base-path";
import { baseUrl } from "@/lib/helper";
import { verifyVrikaEmbedToken } from "@/lib/vrika-embed-token";

function publicRedirectUrl(destPath: string): URL {
  const configured = baseUrl?.trim();
  if (configured) {
    const origin = new URL(
      configured.endsWith("/") ? configured : `${configured}/`,
    ).origin;
    return new URL(destPath, origin);
  }
  throw new Error("AUTH_URL is not configured");
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const token = searchParams.get("token");
  const redirectPath = getSafeCallbackPathFromValue(searchParams.get("redirect"));

  if (!token) {
    return NextResponse.json({ error: "Missing token" }, { status: 400 });
  }

  const secret = process.env.VRIKA_BRIDGE_SECRET?.trim() ?? "";
  const payload = verifyVrikaEmbedToken(token, secret);
  if (!payload) {
    return NextResponse.redirect(new URL(withAppPath("/sign-in"), baseUrl));
  }

  try {
    const destPath =
      redirectPath === "/"
        ? withAppPath("/")
        : redirectPath.startsWith(appBasePath)
          ? redirectPath
          : withAppPath(redirectPath);

    const redirectTarget = publicRedirectUrl(destPath);

    const result = await signIn("social-oauth", {
      accessToken: payload.access,
      refreshToken: payload.refresh,
      redirect: false,
      callbackUrl: redirectTarget.toString(),
    });

    if (result?.error) {
      throw new Error(result.error);
    }

    return NextResponse.redirect(redirectTarget);
  } catch (error) {
    console.error("Vrika embed authentication failed:", error);
    return NextResponse.redirect(new URL(withAppPath("/sign-in"), baseUrl));
  }
}
