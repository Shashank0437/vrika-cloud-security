export const appBasePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

export function withAppPath(path: string): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  return `${appBasePath}${normalized}`;
}

export function stripAppPath(pathname: string): string {
  if (!appBasePath) return pathname;
  if (pathname === appBasePath) return "/";
  if (pathname.startsWith(`${appBasePath}/`)) {
    return pathname.slice(appBasePath.length);
  }
  return pathname;
}

export function authApiBasePath(): string {
  return withAppPath("/api/auth");
}
