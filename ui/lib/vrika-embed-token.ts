import { createHmac, timingSafeEqual } from "crypto";

type EmbedPayload = {
  access: string;
  refresh: string;
  exp: number;
  nonce: string;
};

function b64urlDecode(value: string): Buffer {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  return Buffer.from(value + pad, "base64url");
}

function b64urlEncode(raw: Buffer): string {
  return raw.toString("base64url").replace(/=+$/g, "");
}

export function verifyVrikaEmbedToken(
  token: string,
  secret: string,
): EmbedPayload | null {
  const trimmedSecret = secret.trim();
  if (!trimmedSecret) return null;

  const dot = token.lastIndexOf(".");
  if (dot <= 0) return null;

  const bodyB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = createHmac("sha256", trimmedSecret)
    .update(bodyB64)
    .digest("hex");

  try {
    const a = Buffer.from(sig, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return null;
    }
  } catch {
    return null;
  }

  try {
    const parsed = JSON.parse(b64urlDecode(bodyB64).toString("utf8")) as EmbedPayload;
    if (
      typeof parsed.access !== "string" ||
      typeof parsed.refresh !== "string" ||
      typeof parsed.exp !== "number" ||
      typeof parsed.nonce !== "string"
    ) {
      return null;
    }
    if (parsed.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function mintVrikaEmbedTokenForTest(
  payload: Omit<EmbedPayload, "exp" | "nonce"> & { exp?: number; nonce?: string },
  secret: string,
): string {
  const body = {
    ...payload,
    exp: payload.exp ?? Math.floor(Date.now() / 1000) + 60,
    nonce: payload.nonce ?? "test-nonce",
  };
  const bodyB64 = b64urlEncode(Buffer.from(JSON.stringify(body), "utf8"));
  const sig = createHmac("sha256", secret.trim()).update(bodyB64).digest("hex");
  return `${bodyB64}.${sig}`;
}
