// Domain separation tags for each signing context.
// Prevents cross-context signature confusion when the same key is used across
// multiple message types. Must match across all client implementations.
const DOMAIN_SSE    = "connect.sse.v1\x00";
const DOMAIN_OFFER  = "connect.offer.v1\x00";
const DOMAIN_ANSWER = "connect.answer.v1\x00";
const DOMAIN_ICE    = "connect.ice.v1\x00";

const enc = new TextEncoder();

// Concatenates any mix of Uint8Array and strings (UTF-8 encoded) into one buffer.
function concat(...parts: (Uint8Array | string)[]): Uint8Array<ArrayBuffer> {
  const arrays = parts.map((p) => (typeof p === "string" ? enc.encode(p) : p));
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** URL-safe base64 without padding. Use this for public keys in API surfaces and URL paths. */
export function base64UrlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function base64UrlDecode(str: string): Uint8Array<ArrayBuffer> {
  const std = str.replace(/-/g, "+").replace(/_/g, "/");
  const rem = std.length % 4;
  const padded = rem ? std + "=".repeat(4 - rem) : std;
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}


/** Signed payload for SSE subscription auth: domain || tsBytes */
export function ssePayload(tsBytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return concat(DOMAIN_SSE, tsBytes);
}

/**
 * Signed payload for offer messages:
 *   "connect.offer.v1\0" || challenge[32] || ts[8] || answererPubkey[32] || offerSdp
 *
 * Binds the offer to a specific session (challenge), a freshness window (ts),
 * and the intended recipient (answererPubkey).
 */
export function offerPayload(
  challenge: Uint8Array,
  ts: Uint8Array,
  answererPubkey: Uint8Array,
  offerSdp: string,
): Uint8Array<ArrayBuffer> {
  return concat(DOMAIN_OFFER, challenge, ts, answererPubkey, offerSdp);
}

/**
 * Signed payload for answer messages:
 *   "connect.answer.v1\0" || challenge[32] || ts[8] || offerSdp || "\x00" || answerSdp
 *
 * Binds the answer to the session challenge, a freshness window (ts), and
 * the full offer SDP (which contains the dialer's DTLS fingerprint). The NUL
 * separator keeps concatenation unambiguous across two variable-length strings.
 */
export function answerPayload(
  challenge: Uint8Array,
  ts: Uint8Array,
  offerSdp: string,
  answerSdp: string,
): Uint8Array<ArrayBuffer> {
  return concat(DOMAIN_ANSWER, challenge, ts, offerSdp, "\x00", answerSdp);
}

/**
 * Signed payload for ICE candidate messages:
 *   "connect.ice.v1\0" || challenge[32] || candidateJson
 */
export function icePayload(
  challenge: Uint8Array,
  candidateJson: string,
): Uint8Array<ArrayBuffer> {
  return concat(DOMAIN_ICE, challenge, candidateJson);
}
