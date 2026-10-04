/**
 * poaw_core, ported (SPEC.md §3, §5, §8). Deliberately small and dependency-light, mirroring
 * `oss/core-python/src/poaw_core/__init__.py` byte for byte in intent. No Node built-ins: only
 * Web Crypto-free pure JS (`@noble/curves`, `@noble/hashes`, `canonicalize`) so this runs on
 * Node, Deno and in browsers.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import canonicalizeJcs from "canonicalize";

export const SPEC_VERSION = "poaw/0.1";
export const SIG_DOMAIN = new TextEncoder().encode("POAW-RECEIPT-V0\n");
/** §5.1: a change entry is signed under its own domain, so it can never verify as a receipt. */
export const CHANGE_SIG_DOMAIN = new TextEncoder().encode("POAW-CHANGE-V0\n");
/** §8.5: a signed tree head is signed under its own domain, so it can never verify as a receipt or a change entry. */
export const TREE_HEAD_SIG_DOMAIN = new TextEncoder().encode("POAW-TREE-HEAD-V0\n");

// --- encoding (§3) -----------------------------------------------------------------------------

export function b64u(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(text: string): Uint8Array {
  const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** RFC 8785 JCS, as UTF-8 bytes (matches Python's `rfc8785.dumps`, which returns bytes). */
export function jcs(obj: unknown): Uint8Array {
  const text = canonicalizeJcs(obj as object);
  if (text === undefined) {
    throw new TypeError("jcs: value is not JSON-serializable");
  }
  return new TextEncoder().encode(text);
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * §3: receipts carry integers only. JSON.parse collapses the int/float distinction Python's
 * `json.loads` preserves (e.g. `1.0` parses to the same JS number as `1`), so this checks two
 * ways:
 *  - `hasFloatValue`: any value that is a non-integer finite number (catches every float that
 *    actually matters, e.g. `0.5` in vector 014-float-in-body.json).
 *  - `hasFloatText`: scans the raw JSON text (outside string literals) for a numeric token
 *    containing `.`, `e` or `E` — the same signal Python's tokenizer used to decide `float` vs
 *    `int`, for callers that still have the original text (files, HTTP bodies).
 * `verifyReceipt` OR's both when raw text is available, so nothing is hidden by `JSON.parse`.
 */
export function hasFloatValue(value: unknown): boolean {
  if (typeof value === "boolean") return false;
  if (typeof value === "number") return !Number.isInteger(value);
  if (Array.isArray(value)) return value.some(hasFloatValue);
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).some(hasFloatValue);
  }
  return false;
}

export function hasFloatText(text: string): boolean {
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"') {
      i++;
      while (i < n) {
        if (text[i] === "\\") {
          i += 2;
          continue;
        }
        if (text[i] === '"') {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (ch === "-" || (ch >= "0" && ch <= "9")) {
      const start = i;
      if (ch === "-") i++;
      let sawFloatChar = false;
      while (i < n && text[i] >= "0" && text[i] <= "9") i++;
      if (text[i] === ".") {
        sawFloatChar = true;
        i++;
        while (i < n && text[i] >= "0" && text[i] <= "9") i++;
      }
      if (text[i] === "e" || text[i] === "E") {
        sawFloatChar = true;
        i++;
        if (text[i] === "+" || text[i] === "-") i++;
        while (i < n && text[i] >= "0" && text[i] <= "9") i++;
      }
      if (i === start) i++; // safety, should not happen
      if (sawFloatChar) return true;
      continue;
    }
    i++;
  }
  return false;
}

// --- keys + signatures (§5) ---------------------------------------------------------------------

export function keyId(pkRaw: Uint8Array): string {
  return "ed25519:" + b64u(sha256(pkRaw));
}

export function verifySignature(
  pkRaw: Uint8Array,
  body: unknown,
  sigValue: string,
  domain: Uint8Array = SIG_DOMAIN,
): boolean {
  try {
    const sig = b64uDecode(sigValue);
    const message = concatBytes(domain, jcs(body));
    return ed25519.verify(sig, message, pkRaw);
  } catch {
    return false;
  }
}

/** A body without `entry_kind` is a receipt (undefined). `"change"` is a change entry. Anything else is unknown. */
export function entryKind(body: unknown): unknown {
  return body !== null && typeof body === "object" && !Array.isArray(body)
    ? (body as Record<string, unknown>).entry_kind
    : undefined;
}

/** SPEC §15.2: base64url(SHA-256(JCS(pipeline document))), the same construction as claim_digest. */
export function pipelineDigest(pipeline: unknown): string {
  return b64u(sha256(jcs(pipeline)));
}

export function claimDigest(claim: Record<string, unknown>): string {
  const stripped: Record<string, unknown> = {};
  for (const k of Object.keys(claim)) {
    if (k !== "claim_digest") stripped[k] = claim[k];
  }
  return b64u(sha256(jcs(stripped)));
}

// --- Merkle log, RFC 6962 (§8) ------------------------------------------------------------------

export function leafHash(receipt: { body: unknown; signature: unknown }): Uint8Array {
  return sha256(concatBytes(new Uint8Array([0x00]), jcs({ body: receipt.body, signature: receipt.signature })));
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(new Uint8Array([0x01]), left, right));
}

/** Largest power of two strictly less than n (RFC 6962 §2.1). */
function split(n: number): number {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * RFC 9162 §2.1.3.2 audit-path verification. Returns the computed root, or null if the path is
 * malformed. Ported line for line from `poaw_core.root_from_inclusion`.
 */
export function rootFromInclusion(
  index: number,
  size: number,
  leaf: Uint8Array,
  path: Uint8Array[],
): Uint8Array | null {
  if (index >= size) return null;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return null;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 ? r : null;
}

/**
 * RFC 9162 §2.1.4.2 consistency verification. True iff `proof` shows the size-`m` tree with root `oldRoot` is a prefix of
 * the size-`n` tree with root `newRoot`. Ported line for line from `poaw_core.verify_consistency`.
 */
export function verifyConsistency(
  m: number,
  n: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: Uint8Array[],
): boolean {
  if (!Number.isSafeInteger(m) || !Number.isSafeInteger(n) || !(m > 0 && m <= n)) return false;
  if (m === n) return proof.length === 0 && bytesEqual(oldRoot, newRoot);
  if (proof.length === 0) return false;
  const isPow2 = (x: number) => x > 0 && Number.isInteger(Math.log2(x)) && 2 ** Math.log2(x) === x;
  const path = isPow2(m) ? [oldRoot, ...proof] : [...proof];
  // Plain arithmetic, not bit operators: sizes may exceed 2^31.
  let fn = m - 1;
  let sn = n - 1;
  const odd = (x: number) => x % 2 === 1;
  while (odd(fn)) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (!odd(fn)) {
        while (fn !== 0 && !odd(fn)) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesEqual(fr, oldRoot) && bytesEqual(sr, newRoot);
}

export { bytesEqual };
