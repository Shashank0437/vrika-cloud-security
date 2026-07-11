import { NextRequest } from "next/server";

import { handlers } from "@/auth.config";
import { appBasePath } from "@/lib/base-path";

// Next.js strips basePath before Auth.js sees the request URL.
function withAuthBasePath(req: NextRequest): NextRequest {
  if (!appBasePath) return req;

  const url = new URL(req.url);
  if (!url.pathname.startsWith(appBasePath)) {
    url.pathname = `${appBasePath}${url.pathname}`;
    return new NextRequest(url, req);
  }

  return req;
}

export const GET = (req: NextRequest) => handlers.GET(withAuthBasePath(req));
export const POST = (req: NextRequest) => handlers.POST(withAuthBasePath(req));
