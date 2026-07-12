"use server";

import { NextResponse } from "next/server";

import { signIn } from "@/auth.config";
import { getSafeCallbackPathFromValue } from "@/lib/auth-callback-url";
import { withAppPath, appBasePath } from "@/lib/base-path";
import { baseUrl } from "@/lib/helper";
import { verifyVrikaEmbedToken } from "@/lib/vrika-embed-token";

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

    const result = await signIn("social-oauth", {
      accessToken: payload.access,
      refreshToken: payload.refresh,
      redirect: false,
      callbackUrl: new URL(destPath, req.url).toString(),
    });

    if (result?.error) {
      throw new Error(result.error);
    }

    return NextResponse.redirect(new URL(destPath, req.url));
  } catch (error) {
    console.error("Vrika embed authentication failed:", error);
    return NextResponse.redirect(new URL(withAppPath("/sign-in"), baseUrl));
  }
}
