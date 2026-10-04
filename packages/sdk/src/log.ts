/**
 * Public log checks (SPEC §8.4–§8.5), ported from `oss/spec/tools/check.py`: signed tree heads and consistency proofs.
 * Any doubt gives a failing check, never a pass.
 */
import {
  TREE_HEAD_SIG_DOMAIN,
  b64uDecode,
  keyId,
  verifyConsistency as verifyConsistencyBytes,
  verifySignature,
} from "./primitives.js";
import type { Keyset } from "./anchor.js";

export interface TreeHeadBody {
  log_id: string;
  tree_size: number;
  root_hash: string;
  issued_at: string;
}

export interface TreeHead {
  body: TreeHeadBody;
  signature: { alg: string; key_id: string; value: string };
}

export interface TreeHeadReport {
  valid: boolean;
  checks: { shape: boolean; key: boolean; signature: boolean };
}

/** A `GET /v1/log/consistency` response (SPEC §8.6). */
export interface ConsistencyDoc {
  log_id?: string;
  first: number;
  second: number;
  first_root?: string;
  second_root?: string;
  proof: string[];
}

const HEAD_FIELDS = ["issued_at", "log_id", "root_hash", "tree_size"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * SPEC §8.5: exactly the four body fields with an integer tree_size, a key valid at `issued_at`, and a signature
 * under the tree-head domain. Accepts a bare `{body, signature}` or the `/v1/log/head` response.
 */
export function verifyTreeHead(head: unknown, keys: Keyset): TreeHeadReport {
  const doc = isRecord(head) && isRecord(head.tree_head) ? head.tree_head : head;
  const body = isRecord(doc) ? doc.body : undefined;
  const sig = isRecord(doc) && isRecord(doc.signature) ? doc.signature : {};
  const shape =
    isRecord(body) &&
    Object.keys(body).sort().join(",") === HEAD_FIELDS.join(",") &&
    Number.isInteger(body.tree_size) &&
    (body.tree_size as number) >= 0 &&
    typeof body.log_id === "string" &&
    typeof body.root_hash === "string" &&
    typeof body.issued_at === "string" &&
    sig.alg === "Ed25519";
  let keyOk = false;
  let sigOk = false;
  if (shape) {
    const b = body as unknown as TreeHeadBody;
    const key = (keys.keys ?? []).find((k) => k.key_id === sig.key_id);
    try {
      keyOk = Boolean(
        key &&
          keyId(b64uDecode(key.public_key)) === key.key_id &&
          key.valid_from <= b.issued_at &&
          (key.revoked_at === null || key.revoked_at === undefined || b.issued_at < key.revoked_at),
      );
      sigOk = Boolean(
        keyOk && key && verifySignature(b64uDecode(key.public_key), b, String(sig.value ?? ""), TREE_HEAD_SIG_DOMAIN),
      );
    } catch {
      keyOk = false;
      sigOk = false;
    }
  }
  return { valid: shape && keyOk && sigOk, checks: { shape, key: keyOk, signature: sigOk } };
}

/**
 * SPEC §8.4: `proof` shows the size-`m` tree with root `oldRoot` (base64url) is a prefix of the size-`n` tree with root
 * `newRoot`. The roots come from the caller's own trusted sources, never from the consistency response.
 */
export function verifyConsistency(
  m: number,
  n: number,
  oldRoot: string | Uint8Array,
  newRoot: string | Uint8Array,
  proof: Array<string | Uint8Array>,
): boolean {
  try {
    const bytes = (x: string | Uint8Array) => (typeof x === "string" ? b64uDecode(x) : x);
    return verifyConsistencyBytes(m, n, bytes(oldRoot), bytes(newRoot), proof.map(bytes));
  } catch {
    return false;
  }
}

/** Does `doc` (a `/v1/log/consistency` response) prove old→new for exactly these sizes? */
export function checkConsistencyDoc(doc: unknown, first: number, second: number, oldRoot: string, newRoot: string): boolean {
  if (!isRecord(doc) || doc.first !== first || doc.second !== second || !Array.isArray(doc.proof)) return false;
  return verifyConsistency(first, second, oldRoot, newRoot, doc.proof as string[]);
}

export interface ConsistencySourceOptions {
  /** Consistency responses the caller already holds. */
  consistency?: ConsistencyDoc | ConsistencyDoc[];
  /** The issuer's base URL: a missing proof is fetched from `GET {issuer}/v1/log/consistency?first=&second=`. */
  issuer?: string;
  fetch?: typeof fetch;
}

/** Returns get(first, second): a supplied document for those sizes, else the issuer's, else null (proof required). */
export function consistencySource(opts: ConsistencySourceOptions = {}): (first: number, second: number) => Promise<ConsistencyDoc | null> {
  const supplied = opts.consistency === undefined ? [] : Array.isArray(opts.consistency) ? opts.consistency : [opts.consistency];
  return async (first, second) => {
    const have = supplied.find((d) => d && d.first === first && d.second === second);
    if (have) return have;
    if (!opts.issuer) return null;
    try {
      const f = opts.fetch ?? globalThis.fetch;
      const res = await f(`${opts.issuer.replace(/\/+$/, "")}/v1/log/consistency?first=${first}&second=${second}`, {
        headers: { accept: "application/json" },
      });
      if (!res.ok) return null;
      return (await res.json()) as ConsistencyDoc;
    } catch {
      return null;
    }
  };
}

export type GetConsistency = (first: number, second: number) => Promise<ConsistencyDoc | null>;

/**
 * SPEC §8.5 + §8.4: the head's signature verifies and, when the receipt has a proof, the receipt's tree is a prefix of the
 * head's. Resolves to `true` or a reason string.
 */
export async function checkHead(
  head: unknown,
  proof: { log_id: string; tree_size: number; root_hash: string } | undefined,
  keys: Keyset,
  get: GetConsistency,
): Promise<true | string> {
  const r = verifyTreeHead(head, keys);
  if (!r.valid) return "head_signature_invalid";
  const hd = (isRecord(head) && isRecord(head.tree_head) ? head.tree_head : head) as TreeHead;
  if (!proof) return true;
  const hb = hd.body;
  if (hb.log_id !== proof.log_id) return "log_mismatch";
  const m = proof.tree_size;
  const n = hb.tree_size;
  if (m > n) return "head_older_than_receipt";
  if (m === n) return hb.root_hash === proof.root_hash ? true : "root_mismatch";
  const doc = await get(m, n);
  if (!doc) return "consistency_proof_required";
  return checkConsistencyDoc(doc, m, n, proof.root_hash, hb.root_hash) ? true : "not_consistent";
}
