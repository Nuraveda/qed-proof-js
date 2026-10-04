/**
 * SPEC §8.4–§8.5: verifyConsistency against every (m, n) of a real tree, signed tree heads, and the anchor check with a
 * consistency proof in both directions. The tree is built with the same RFC 6962 construction as `poaw_core`.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { b64u, jcs, keyId, sha256, TREE_HEAD_SIG_DOMAIN, SIG_DOMAIN, verifyConsistency as verifyBytes } from "../src/primitives.js";
import { checkHead, consistencySource, verifyConsistency, verifyTreeHead, type ConsistencyDoc } from "../src/log.js";
import { verifyReceipt } from "../src/verify.js";

const enc = new TextEncoder();
const cat = (...p: Uint8Array[]) => Uint8Array.from(p.flatMap((x) => [...x]));
const node = (l: Uint8Array, r: Uint8Array) => sha256(cat(Uint8Array.of(1), l, r));
const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const LEAVES = Array.from({ length: 12 }, (_, i) => sha256(cat(Uint8Array.of(0), enc.encode(`leaf-${i}`))));
const mth = (l: Uint8Array[]): Uint8Array => (l.length === 1 ? l[0] : node(mth(l.slice(0, split(l.length))), mth(l.slice(split(l.length)))));
/** RFC 6962 PROOF(m, D[n]) */
function proof(m: number, n: number): Uint8Array[] {
  const sub = (mm: number, d: Uint8Array[], b: boolean): Uint8Array[] => {
    if (mm === d.length) return b ? [] : [mth(d)];
    const k = split(d.length);
    return mm <= k ? [...sub(mm, d.slice(0, k), b), mth(d.slice(k))] : [...sub(mm - k, d.slice(k), false), mth(d.slice(0, k))];
  };
  return sub(m, LEAVES.slice(0, n), true);
}
const root = (n: number) => mth(LEAVES.slice(0, n));
const doc = (m: number, n: number): ConsistencyDoc => ({ first: m, second: n, proof: proof(m, n).map(b64u) });

describe("verifyConsistency (RFC 9162 §2.1.4.2)", () => {
  it("accepts the honest proof for every 0 < m <= 12 and n >= m", () => {
    for (let n = 1; n <= 12; n++) for (let m = 1; m <= n; m++) {
      expect(verifyBytes(m, n, root(m), root(n), proof(m, n)), `${m}->${n}`).toBe(true);
    }
  });
  it("rejects a wrong old root, a wrong new root, an altered, missing or extra node", () => {
    const p = proof(3, 7);
    expect(verifyBytes(3, 7, sha256(enc.encode("x")), root(7), p)).toBe(false);
    expect(verifyBytes(3, 7, root(3), sha256(enc.encode("x")), p)).toBe(false);
    expect(verifyBytes(3, 7, root(3), root(7), [sha256(enc.encode("x")), ...p.slice(1)])).toBe(false);
    expect(verifyBytes(3, 7, root(3), root(7), p.slice(1))).toBe(false);
    expect(verifyBytes(3, 7, root(3), root(7), [...p, p[0]])).toBe(false);
    expect(verifyBytes(3, 7, root(3), root(7), [])).toBe(false);
  });
  it("rejects bad sizes; m = n needs an empty proof and equal roots", () => {
    expect(verifyBytes(0, 7, root(1), root(7), [])).toBe(false);
    expect(verifyBytes(8, 7, root(8), root(7), [])).toBe(false);
    expect(verifyBytes(5, 5, root(5), root(5), [])).toBe(true);
    expect(verifyBytes(5, 5, root(5), root(5), [root(5)])).toBe(false);
    expect(verifyBytes(5, 5, root(5), root(6), [])).toBe(false);
  });
  it("accepts base64url strings and swallows malformed input", () => {
    const d = doc(3, 7);
    expect(verifyConsistency(3, 7, b64u(root(3)), b64u(root(7)), d.proof)).toBe(true);
    expect(verifyConsistency(3, 7, "!!!", b64u(root(7)), d.proof)).toBe(false);
  });
});

const SK = ed25519.utils.randomPrivateKey();
const PK = ed25519.getPublicKey(SK);
const KEYS = { keys: [{ key_id: keyId(PK), public_key: b64u(PK), valid_from: "2026-01-01T00:00:00.000Z", revoked_at: null }] };
const LOG_ID = b64u(sha256(enc.encode("log")));
function head(size: number, domain: Uint8Array = TREE_HEAD_SIG_DOMAIN) {
  const body = { log_id: LOG_ID, tree_size: size, root_hash: b64u(root(size)), issued_at: "2026-09-25T14:05:00.000Z" };
  return { body, signature: { alg: "Ed25519", key_id: keyId(PK), value: b64u(ed25519.sign(cat(domain, jcs(body)), SK)) } };
}

describe("verifyTreeHead", () => {
  it("valid head; also accepts the /v1/log/head response shape", () => {
    expect(verifyTreeHead(head(9), KEYS).valid).toBe(true);
    expect(verifyTreeHead({ tree_head: head(9), anchor: null }, KEYS).valid).toBe(true);
  });
  it("tampered size, receipt domain, extra field, unknown or future key all fail", () => {
    const t = head(9); t.body.tree_size = 10;
    expect(verifyTreeHead(t, KEYS).checks).toEqual({ shape: true, key: true, signature: false });
    expect(verifyTreeHead(head(9, SIG_DOMAIN), KEYS).valid).toBe(false);
    const x = head(9) as { body: Record<string, unknown> }; x.body.extra = 1;
    expect(verifyTreeHead(x, KEYS).checks.shape).toBe(false);
    expect(verifyTreeHead(head(9), { keys: [] }).valid).toBe(false);
    expect(verifyTreeHead(head(9), { keys: [{ ...KEYS.keys[0], valid_from: "2027-01-01T00:00:00.000Z" }] }).valid).toBe(false);
    expect(verifyTreeHead(head(9), { keys: [{ ...KEYS.keys[0], revoked_at: "2026-09-25T14:05:00.000Z" }] }).valid).toBe(false);
    const f = head(9); (f.body as { tree_size: unknown }).tree_size = 9.5;
    expect(verifyTreeHead(f, KEYS).checks.shape).toBe(false);
    expect(verifyTreeHead(null, KEYS).valid).toBe(false);
  });
});

describe("checkHead", () => {
  const pr = (size: number) => ({ log_id: LOG_ID, tree_size: size, root_hash: b64u(root(size)) });
  it("receipt tree is a prefix of the head, supplied or fetched from the issuer", async () => {
    expect(await checkHead(head(9), pr(6), KEYS, consistencySource({ consistency: [doc(6, 9)] }))).toBe(true);
    const f = vi.fn(async () => new Response(JSON.stringify(doc(6, 9)))) as unknown as typeof fetch;
    expect(await checkHead(head(9), pr(6), KEYS, consistencySource({ issuer: "https://api.example.test/", fetch: f }))).toBe(true);
    expect((f as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0]).toBe("https://api.example.test/v1/log/consistency?first=6&second=9");
  });
  it("fails without a proof, with a forged proof, with an older head, and for another log", async () => {
    expect(await checkHead(head(9), pr(6), KEYS, consistencySource())).toBe("consistency_proof_required");
    const bad = doc(6, 9); bad.proof[0] = b64u(sha256(enc.encode("forged")));
    expect(await checkHead(head(9), pr(6), KEYS, consistencySource({ consistency: bad }))).toBe("not_consistent");
    expect(await checkHead(head(4), pr(6), KEYS, consistencySource())).toBe("head_older_than_receipt");
    expect(await checkHead(head(6), pr(6), KEYS, consistencySource())).toBe(true);
    expect(await checkHead(head(9), { ...pr(6), log_id: "other" }, KEYS, consistencySource({ consistency: doc(6, 9) }))).toBe("log_mismatch");
    expect(await checkHead({ nope: 1 }, pr(6), KEYS, consistencySource())).toBe("head_signature_invalid");
  });
  it("a fetch failure leaves the proof required, never a pass", async () => {
    const f = vi.fn(async () => { throw new Error("down"); }) as unknown as typeof fetch;
    expect(await checkHead(head(9), pr(6), KEYS, consistencySource({ issuer: "https://x.test", fetch: f }))).toBe("consistency_proof_required");
  });
});

describe("verifyReceipt with a head", () => {
  it("adds checks.head and makes validity depend on it", async () => {
    const r = JSON.parse(JSON.stringify((await import("node:fs")).readFileSync(new URL("../../../test/vectors/016-inclusion-first-leaf.json", import.meta.url), "utf-8")));
    const keys = JSON.parse((await import("node:fs")).readFileSync(new URL("../../../test/vectors/keys.json", import.meta.url), "utf-8"));
    const base = await verifyReceipt(r, { keys });
    expect(base.checks).not.toHaveProperty("head");
    expect(base.valid).toBe(true);
    const withHead = await verifyReceipt(r, { keys, head: { body: {}, signature: {} } });
    expect(withHead.checks.head).toBe("head_signature_invalid");
    expect(withHead.valid).toBe(false);
  });
});

afterEach(() => vi.restoreAllMocks());
