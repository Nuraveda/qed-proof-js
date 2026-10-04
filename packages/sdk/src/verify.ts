/**
 * Reference checker for PoAW receipts (SPEC.md §10), ported from `oss/spec/tools/check.py` and
 * `oss/spec/tools/anchor_check.py`. Offline it checks steps 1-4. With `rpcUrl` it also checks the
 * anchor against the chain (§8.4). Any doubt gives a failing check, never a pass.
 */
import {
  b64uDecode,
  CHANGE_SIG_DOMAIN,
  SIG_DOMAIN,
  claimDigest,
  entryKind,
  pipelineDigest,
  hasFloatValue,
  hasFloatText,
  keyId,
  leafHash,
  rootFromInclusion,
  verifySignature,
  b64u,
} from "./primitives.js";
import { changeSchemaValid, pipelineSchemaValid, schemaValid } from "./schema.js";
import { checkAnchor, type Keyset, type Proof } from "./anchor.js";
import { checkHead, consistencySource, type ConsistencyDoc } from "./log.js";

export interface VerifyChecks {
  spec_version: boolean;
  schema: boolean;
  integers_only: boolean;
  key: boolean;
  signature: boolean;
  /** Absent on a change entry (§14.1: it has no claim). */
  claim_digest?: boolean;
  inclusion: boolean | "absent";
  anchor: boolean | "absent" | "not_checked_offline" | string;
  /** Present only when the body carries a `policy` (§15.2). "not_checked" when no pipeline document was given. */
  policy?: boolean | "not_checked";
  /** Present only when a signed tree head was supplied (§8.5): true, or why the receipt's tree isn't proven part of it. */
  head?: boolean | string;
}

export interface VerifyReport {
  checks: VerifyChecks;
  valid: boolean;
  verdict: string | null;
  achieved_trust_level: number;
  proven_by?: number | null;
  /** "change" for a change entry (§14); absent for a receipt. */
  entry_kind?: "change";
}

export interface VerifyOptions {
  keys: Keyset;
  rpcUrl?: string;
  /** The pipeline document the entry's `policy` points at (§15.2). Without it, `checks.policy` is "not_checked". */
  pipeline?: unknown;
  /**
   * Consistency proofs (SPEC §8.4) the caller already holds, shaped like `GET /v1/log/consistency`. Used when the anchor's
   * tree size differs from the receipt's proof, and to connect the receipt's tree to `head`.
   */
  consistency?: ConsistencyDoc | ConsistencyDoc[];
  /** The issuer's base URL: a needed consistency proof not supplied is fetched from its `/v1/log/consistency`. */
  issuer?: string;
  /** A signed tree head (§8.5): a bare `{body, signature}` or the `/v1/log/head` response. Adds `checks.head`. */
  head?: unknown;
  /** The fetch used for `issuer` requests. Defaults to the global one. */
  fetch?: typeof fetch;
}

/** SPEC §15.2: the document is valid, its id and version are the policy's, and its digest is the policy's. */
function checkPolicy(policy: Record<string, unknown>, pipeline: unknown): boolean {
  if (pipeline === null || typeof pipeline !== "object" || Array.isArray(pipeline)) return false;
  const p = pipeline as Record<string, unknown>;
  try {
    return (
      !hasFloatValue(pipeline) &&
      pipelineSchemaValid(pipeline) &&
      p.id === policy.pipeline_id &&
      p.version === policy.pipeline_version &&
      pipelineDigest(pipeline) === policy.digest
    );
  } catch {
    return false;
  }
}

interface ReceiptLike {
  body?: Record<string, unknown>;
  signature?: { key_id?: string; value?: string };
  proof?: Proof;
  [key: string]: unknown;
}

/**
 * Verify a PoAW receipt. `receipt` may be a parsed object or the raw JSON text — passing the raw
 * text lets the integers-only check catch a float written as e.g. `1.0` (indistinguishable from
 * the integer `1` after `JSON.parse`), matching Python's `json.loads` int/float distinction
 * exactly; a non-integer value like `0.5` is caught either way.
 */
/**
 * The JSON text each receipt object was parsed from, when the SDK fetched it (`QedProof.getReceipt`). JSON.parse turns
 * `1.0` into `1`, which would hide a float SPEC §3 forbids, so verification reads the original text when it has it.
 * That way a fetched receipt verifies exactly as it does in the Python SDK and the reference checker.
 */
export const RECEIPT_TEXT = new WeakMap<object, string>();

export async function verifyReceipt(receipt: unknown | string, options: VerifyOptions): Promise<VerifyReport> {
  const raw = typeof receipt === "string" ? receipt
    : receipt && typeof receipt === "object" ? RECEIPT_TEXT.get(receipt as object) : undefined;
  const parsed: ReceiptLike = typeof receipt === "string" ? JSON.parse(receipt) : ((receipt as ReceiptLike) ?? {});
  const keyset = options.keys ?? {};

  const checks = {} as VerifyChecks;

  const body = (parsed && typeof parsed === "object" ? parsed.body : undefined) ?? {};
  const version = String((body as Record<string, unknown>).spec_version ?? "");
  const parts = version.split("/");
  checks.spec_version = parts[0] === "poaw" && (parts[parts.length - 1] ?? "").split(".")[0] === "0";

  // §14: no entry_kind is a receipt, "change" is a change entry, anything else is not an entry this spec defines.
  const kind = entryKind(body);
  const isChange = kind === "change";
  checks.schema = (kind === undefined || isChange) && (isChange ? changeSchemaValid(parsed) : schemaValid(parsed));

  const integerFail = raw !== undefined ? hasFloatText(raw) : hasFloatValue(parsed);
  checks.integers_only = !integerFail;

  const sig = (parsed && typeof parsed === "object" ? parsed.signature : undefined) ?? ({} as ReceiptLike["signature"]);
  const keys = keyset.keys ?? [];
  const key = keys.find((k) => k.key_id === sig?.key_id);
  const issued = String((body as Record<string, unknown>).issued_at ?? "");
  const issuer = (body as Record<string, unknown>).issuer as { key_id?: string } | undefined;

  let keyOk = false;
  if (key && sig?.key_id === issuer?.key_id) {
    try {
      const computedKeyId = keyId(b64uDecode(key.public_key));
      keyOk =
        computedKeyId === key.key_id &&
        key.valid_from <= issued &&
        (key.revoked_at === null || key.revoked_at === undefined || issued < key.revoked_at);
    } catch {
      keyOk = false;
    }
  }
  checks.key = keyOk;

  let sigOk = false;
  if (keyOk && key) {
    try {
      sigOk = verifySignature(b64uDecode(key.public_key), body, sig?.value ?? "", isChange ? CHANGE_SIG_DOMAIN : SIG_DOMAIN);
    } catch {
      sigOk = false;
    }
  }
  checks.signature = sigOk;

  if (!isChange) {
    const claim = (body as Record<string, unknown>).claim;
    checks.claim_digest =
      Boolean(claim) &&
      typeof claim === "object" &&
      (claim as Record<string, unknown>).claim_digest === claimDigest(claim as Record<string, unknown>);
  }

  const proof = parsed && typeof parsed === "object" ? parsed.proof : undefined;
  const getConsistency = consistencySource({ consistency: options.consistency, issuer: options.issuer, fetch: options.fetch });
  let provenBy: number | null | undefined;
  if (!proof) {
    checks.inclusion = "absent";
  } else {
    const root = rootFromInclusion(
      proof.leaf_index,
      proof.tree_size,
      leafHash({ body: (parsed as ReceiptLike).body, signature: (parsed as ReceiptLike).signature }),
      proof.inclusion.map((h) => b64uDecode(h)),
    );
    checks.inclusion = root !== null && b64u(root) === proof.root_hash;
  }

  if (!(proof && proof.anchor)) {
    checks.anchor = "absent";
  } else if (!options.rpcUrl) {
    checks.anchor = "not_checked_offline";
  } else {
    const a = await checkAnchor(proof, keyset, options.rpcUrl, getConsistency);
    checks.anchor = a.ok ? true : a.reason;
    provenBy = a.proven_by;
  }

  if (options.head !== undefined && options.head !== null) {
    checks.head = await checkHead(options.head, proof, keyset, getConsistency);
  }

  // §15.2: only present when the body carries a policy. Without the pipeline document it is "not_checked".
  const policy = (body as Record<string, unknown>).policy;
  if (policy !== undefined && policy !== null) {
    checks.policy =
      options.pipeline === undefined || options.pipeline === null
        ? "not_checked"
        : typeof policy === "object" && !Array.isArray(policy) && checkPolicy(policy as Record<string, unknown>, options.pipeline);
  }

  const required: Array<keyof VerifyChecks> = ["spec_version", "schema", "integers_only", "key", "signature"];
  if (!isChange) required.push("claim_digest");
  const valid =
    required.every((k) => checks[k] === true) &&
    (checks.inclusion === true || checks.inclusion === "absent") &&
    (checks.policy === undefined || checks.policy === true || checks.policy === "not_checked") &&
    (checks.head === undefined || checks.head === true);

  const achievedTrustLevel = valid ? (checks.inclusion === true && checks.anchor === true ? 2 : 1) : 0;
  const verdictValue = (body as Record<string, unknown>).verdict as { value?: string } | undefined;
  const verdict = valid && !isChange ? (verdictValue?.value ?? null) : null;

  const report: VerifyReport = {
    checks,
    valid,
    verdict: verdict ?? null,
    achieved_trust_level: achievedTrustLevel,
  };
  if (isChange) {
    report.entry_kind = "change";
  }
  if (provenBy !== undefined) {
    report.proven_by = provenBy;
  }
  return report;
}
