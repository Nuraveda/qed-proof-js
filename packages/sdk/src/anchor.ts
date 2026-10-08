/**
 * SPEC §8.4: check a receipt's `proof.anchor` (scheme `eas`) against a public JSON-RPC endpoint.
 * Ported from `oss/spec/tools/anchor_check.py`. Any doubt gives `ok: false` — never a pass.
 */
import { keccak_256 } from "@noble/hashes/sha3";
import { b64uDecode, b64u, bytesEqual } from "./primitives.js";
import { checkConsistencyDoc, type GetConsistency } from "./log.js";
import { decodeSingleDynamicTupleReturn, decodeTupleWithTrailingDynamic, bytesToHex0x, hexToBytes } from "./abi.js";

const EAS = "0x4200000000000000000000000000000000000021"; // OP-stack predeploy (Base mainnet + Base Sepolia)

function selector(signature: string): Uint8Array {
  return keccak_256(new TextEncoder().encode(signature)).slice(0, 4);
}

const GET_SELECTOR = selector("getAttestation(bytes32)");
const ATT_STATIC_KINDS = ["bytes32", "bytes32", "uint64", "uint64", "uint64", "bytes32", "address", "address", "bool"] as const;
const DATA_STATIC_KINDS = ["bytes32", "uint64", "bytes32", "uint64", "bytes32"] as const;

export interface Proof {
  log_id: string;
  leaf_index: number;
  tree_size: number;
  root_hash: string;
  inclusion: string[];
  anchor?: {
    chain: string;
    scheme: string;
    uid: string;
    tx_hash: string;
    tree_size: number;
  };
}

export interface Keyset {
  keys?: Array<{ key_id: string; public_key: string; valid_from: string; revoked_at: string | null }>;
  anchor_addresses?: string[];
  anchor_schemas?: string[];
  /** Published enclave builds (SPEC §5.2): the attested PCR0 must equal one of their `code_hash` values at trust level 3. */
  verifier_builds?: Array<{ code_hash: string; [key: string]: unknown }>;
}

export interface AnchorResult {
  ok: boolean;
  reason: string;
  proven_by: number | null;
}

async function rpc(url: string, method: string, ...params: unknown[]): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "qed-proof-sdk-js/0.1" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await res.json()) as { error?: { message?: string }; result?: unknown };
  if (body && body.error) {
    throw new Error(`${method}: ${body.error.message ?? "rpc error"}`);
  }
  return body.result;
}

/** Return {ok, reason, proven_by}. Any doubt → ok false, never a pass. */
export async function checkAnchor(
  proof: Proof,
  keyset: Keyset,
  rpcUrl: string,
  /** Returns a `/v1/log/consistency` response for (first, second), or null. Only consulted when the sizes differ. */
  getConsistency?: GetConsistency,
): Promise<AnchorResult> {
  const a = proof.anchor;
  if (!a) return { ok: false, reason: "unknown_scheme", proven_by: null };
  try {
    if (a.scheme !== "eas") return { ok: false, reason: "unknown_scheme", proven_by: null };

    const chainIdHex = (await rpc(rpcUrl, "eth_chainId")) as string;
    const wantChainId = a.chain.split(":")[1];
    if (BigInt(chainIdHex) !== BigInt(wantChainId)) {
      return { ok: false, reason: "rpc_chain_mismatch", proven_by: null };
    }

    const uid = hexToBytes(a.uid);
    const callData = new Uint8Array([...GET_SELECTOR, ...uid]);
    const out = (await rpc(rpcUrl, "eth_call", { to: EAS, data: bytesToHex0x(callData) }, "latest")) as string;
    const returnData = hexToBytes(out);
    const { statics, dynamic } = decodeSingleDynamicTupleReturn(returnData, [...ATT_STATIC_KINDS], "bytes");
    const [uid_, schema, time_, _exp, revokedAt, _ref, _recipient, attester, _revocable] = statics as [
      Uint8Array,
      Uint8Array,
      bigint,
      bigint,
      bigint,
      Uint8Array,
      Uint8Array,
      string,
      boolean,
    ];
    const data = dynamic as Uint8Array;

    if (!bytesEqual(uid_, uid) || time_ === 0n) {
      return { ok: false, reason: "attestation_not_found", proven_by: null };
    }
    if (revokedAt !== 0n) {
      return { ok: false, reason: "attestation_revoked", proven_by: null };
    }
    const attesterLower = (attester as string).toLowerCase();
    const publishedAttesters = new Set((keyset.anchor_addresses ?? []).map((x) => x.toLowerCase()));
    if (!publishedAttesters.has(attesterLower)) {
      return { ok: false, reason: "attester_not_published", proven_by: null };
    }
    const schemaHex = "0x" + bytesToHex0x(schema).slice(2);
    const publishedSchemas = new Set((keyset.anchor_schemas ?? []).map((x) => x.toLowerCase()));
    if (!publishedSchemas.has(schemaHex.toLowerCase())) {
      return { ok: false, reason: "schema_not_published", proven_by: null };
    }

    let decodedData: { statics: unknown[]; dynamic: unknown };
    try {
      decodedData = decodeTupleWithTrailingDynamic(data, [...DATA_STATIC_KINDS], "string");
    } catch {
      return { ok: false, reason: "data_undecodable", proven_by: null };
    }
    const [logId, size, root, _prevSize, _prevRoot] = decodedData.statics as [Uint8Array, bigint, Uint8Array, bigint, Uint8Array];

    if (!bytesEqual(logId, b64uDecode(proof.log_id)) || size !== BigInt(a.tree_size)) {
      return { ok: false, reason: "log_or_size_mismatch", proven_by: null };
    }
    if (a.tree_size < proof.tree_size && !(Number.isInteger(proof.leaf_index) && proof.leaf_index >= 0 && proof.leaf_index < a.tree_size)) {
      // §8.4: an anchor of a smaller tree only covers its own leaves; a leaf appended after it gets no proven-by time.
      return { ok: false, reason: "anchor_does_not_cover_leaf", proven_by: null };
    }
    if (a.tree_size !== proof.tree_size) {
      // §8.4: connect the attested root and the receipt's root with a consistency proof. The smaller tree is the old one.
      const doc = getConsistency ? await getConsistency(Math.min(a.tree_size, proof.tree_size), Math.max(a.tree_size, proof.tree_size)) : null;
      if (!doc) return { ok: false, reason: "consistency_proof_required", proven_by: null };
      const chainRoot = b64u(root);
      const connected =
        a.tree_size < proof.tree_size
          ? checkConsistencyDoc(doc, a.tree_size, proof.tree_size, chainRoot, proof.root_hash)
          : checkConsistencyDoc(doc, proof.tree_size, a.tree_size, proof.root_hash, chainRoot);
      if (!connected) return { ok: false, reason: "consistency_proof_invalid", proven_by: null };
      return { ok: true, reason: "anchored", proven_by: Number(time_) };
    }
    if (!bytesEqual(root, b64uDecode(proof.root_hash))) {
      return { ok: false, reason: "root_mismatch", proven_by: null };
    }
    return { ok: true, reason: "anchored", proven_by: Number(time_) };
  } catch (exc) {
    const name = exc instanceof Error ? exc.constructor.name : "Error";
    return { ok: false, reason: `unreadable:${name}`, proven_by: null };
  }
}
