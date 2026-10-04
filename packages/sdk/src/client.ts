/**
 * The HTTP client. Shapes follow `oss/node/src/poaw_node/app.py`, `models.py` (`ClaimIn`) and
 * `store.py` (`claim_status`). Uses only `fetch` — no Node built-ins — so it runs on Node, Deno
 * and in browsers.
 */
import type { ClaimAction } from "./actions.js";
import { QedProofError, RateLimitError } from "./errors.js";
import { RECEIPT_TEXT, verifyReceipt, type VerifyOptions, type VerifyReport } from "./verify.js";
import type { Keyset } from "./anchor.js";
import type { ConsistencyDoc, TreeHead } from "./log.js";

export interface QedProofOptions {
  apiKey?: string;
  baseUrl?: string;
  fetch?: typeof fetch;
}

export interface SubmitClaimOptions {
  agentId: string;
  clientClaimId?: string;
  claimedAt?: string | Date;
}

export interface ClaimStatus {
  claim_id: string;
  created?: boolean;
  state: "queued" | "decided";
  attempts: number;
  receipt_id: string | null;
  verdict: string | null;
}

export interface WaitOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export interface Receipt {
  body: Record<string, unknown>;
  signature: Record<string, unknown>;
  proof?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ClaimSummary {
  claim_id: string;
  state: string;
  attempts: number;
  receipt_id: string | null;
  verdict: string | null;
}

export interface ListClaimsOptions {
  limit?: number;
  cursor?: string;
  agentId?: string;
  action?: string;
  verdict?: string;
  state?: string;
}

export interface ClaimPage {
  claims: ClaimSummary[];
  nextCursor: string | null;
}

/** A landed on-chain anchor of a tree head (SPEC §8.4). */
export interface LogAnchor {
  chain: string;
  scheme: string;
  uid: string;
  tx_hash: string;
  tree_size: number;
  root_hash: string;
  block_number: number;
  block_time: string;
  [key: string]: unknown;
}

/** `GET /v1/log/head`: the signed tree head and the latest landed anchor (or null). */
export interface LogHead {
  tree_head: TreeHead;
  anchor: LogAnchor | null;
}

/** `GET /v1/log/consistency`: an RFC 6962 consistency proof between two tree sizes. */
export type LogConsistency = ConsistencyDoc & { log_id: string; first_root: string; second_root: string };

/** `GET /v1/log/proof`: an inclusion proof for one leaf. */
export interface LogInclusionProof {
  log_id: string;
  leaf_index: number;
  tree_size: number;
  leaf_hash: string;
  root_hash: string;
  inclusion: string[];
}

export interface LogAnchorsOptions {
  /** 1-100, default 20 (server side). */
  limit?: number;
  /** Return anchors with a tree size below this one (the previous page's `next`). */
  before?: number;
}

export interface LogAnchorPage {
  anchors: LogAnchor[];
  next: number | null;
}

export interface LogEntriesOptions {
  /** First leaf index; server default is the newest page. */
  start?: number;
  /** 1-100, default 50 (server side). */
  limit?: number;
}

export interface LogEntry {
  leaf_index: number;
  leaf_hash: string;
  created_at: string;
}

export interface LogEntryPage {
  tree_size: number;
  entries: LogEntry[];
  next: number | null;
}

const LIST_CLAIMS_DEFAULT_LIMIT = 50;
const LIST_CLAIMS_MIN_LIMIT = 1;
const LIST_CLAIMS_MAX_LIMIT = 200;

const DEFAULT_BASE_URL = "https://api.qedproof.site";

function isoNow(): string {
  return new Date().toISOString();
}

export class QedProof {
  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: QedProofOptions = {}) {
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    const f = options.fetch ?? globalThis.fetch;
    if (!f) {
      throw new Error("QedProof: no fetch implementation available; pass { fetch } explicitly");
    }
    // Call fetch as a plain function, never as a method of this client: browsers throw "Illegal invocation" when
    // fetch's `this` isn't the window (Node doesn't care, so 0.1.0-0.1.3 worked in Node and failed in every browser).
    this.fetchImpl = (input, init) => f(input, init);
  }

  private async request(
    method: string,
    path: string,
    { auth = true, body, text = false }: { auth?: boolean; body?: unknown; text?: boolean } = {},
  ): Promise<unknown> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (auth) {
      if (!this.apiKey) {
        throw new QedProofError(401, "no API key configured");
      }
      headers["authorization"] = `Bearer ${this.apiKey}`;
    }
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (exc) {
      // Never let a network failure leak the key: the message here never includes `this.apiKey`.
      throw new QedProofError(0, `network error: ${exc instanceof Error ? exc.message : String(exc)}`);
    }

    if (res.status === 429) {
      const retryAfterHeader = res.headers.get("retry-after");
      const retryAfter = retryAfterHeader ? Number(retryAfterHeader) : undefined;
      let detail = "rate limit exceeded";
      try {
        const parsed = (await res.json()) as { detail?: string };
        if (parsed?.detail) detail = parsed.detail;
      } catch {
        // ignore body parse failure, keep default detail
      }
      throw new RateLimitError(detail, Number.isFinite(retryAfter) ? retryAfter : undefined);
    }

    if (!res.ok) {
      let detail = res.statusText;
      try {
        const parsed = (await res.json()) as { detail?: string };
        if (parsed?.detail) detail = parsed.detail;
      } catch {
        // ignore body parse failure, keep statusText
      }
      throw new QedProofError(res.status, detail);
    }

    if (res.status === 204) return undefined;
    if (text) return res.text();
    return res.json();
  }

  async submitClaim(claim: ClaimAction, options: SubmitClaimOptions): Promise<ClaimStatus> {
    const claimedAt = options.claimedAt instanceof Date ? options.claimedAt.toISOString() : (options.claimedAt ?? isoNow());
    const body = {
      client_claim_id: options.clientClaimId ?? cryptoRandomId(),
      agent_id: options.agentId,
      action: claim.action,
      target: claim.target,
      params: claim.params,
      claimed_at: claimedAt,
    };
    return (await this.request("POST", "/v1/claims", { body })) as ClaimStatus;
  }

  async getClaim(claimId: string): Promise<ClaimStatus> {
    return (await this.request("GET", `/v1/claims/${encodeURIComponent(claimId)}`)) as ClaimStatus;
  }

  async waitForVerdict(claimId: string, options: WaitOptions = {}): Promise<ClaimStatus> {
    const timeoutMs = options.timeoutMs ?? 120_000;
    const pollIntervalMs = options.pollIntervalMs ?? 2_000;
    const deadline = Date.now() + timeoutMs;
    let interval = pollIntervalMs;
    for (;;) {
      let wait = interval;
      try {
        const status = await this.getClaim(claimId);
        if (status.state === "decided") return status;
      } catch (exc) {
        if (exc instanceof RateLimitError && exc.retryAfter !== undefined) {
          wait = Math.max(wait, exc.retryAfter * 1000);
        } else {
          throw exc;
        }
      }
      if (Date.now() >= deadline) {
        throw new QedProofError(408, `timed out after ${timeoutMs}ms waiting for claim ${claimId} to decide`);
      }
      await sleep(Math.min(wait, Math.max(0, deadline - Date.now())));
      interval = Math.min(interval * 2, 30_000);
    }
  }

  /**
   * `GET /v1/claims`, newest first. `options.limit` (1-200, default 50) is validated locally —
   * out of range throws a `RangeError` before any request is made.
   */
  async listClaims(options: ListClaimsOptions = {}): Promise<ClaimPage> {
    const limit = options.limit ?? LIST_CLAIMS_DEFAULT_LIMIT;
    if (limit < LIST_CLAIMS_MIN_LIMIT || limit > LIST_CLAIMS_MAX_LIMIT) {
      throw new RangeError(`limit must be between ${LIST_CLAIMS_MIN_LIMIT} and ${LIST_CLAIMS_MAX_LIMIT}, got ${limit}`);
    }
    const query: Record<string, string> = { limit: String(limit) };
    if (options.cursor !== undefined) query.cursor = options.cursor;
    if (options.agentId !== undefined) query.agent_id = options.agentId;
    if (options.action !== undefined) query.action = options.action;
    if (options.verdict !== undefined) query.verdict = options.verdict;
    if (options.state !== undefined) query.state = options.state;
    const qs = new URLSearchParams(query).toString();
    const data = (await this.request("GET", `/v1/claims?${qs}`)) as { claims: ClaimSummary[]; next_cursor: string | null };
    return { claims: data.claims, nextCursor: data.next_cursor };
  }

  /** Yields every claim matching the filters, following `nextCursor` until exhausted. */
  async *iterClaims(options: Omit<ListClaimsOptions, "cursor" | "limit"> & { pageSize?: number } = {}): AsyncGenerator<ClaimSummary> {
    const { pageSize, ...filters } = options;
    let cursor: string | undefined;
    for (;;) {
      const page = await this.listClaims({ ...filters, limit: pageSize, cursor });
      yield* page.claims;
      if (page.nextCursor === null) return;
      cursor = page.nextCursor;
    }
  }

  /** Receipts are designed to be shared and checked by anyone (SPEC §1): no Authorization header. */
  async getReceipt(receiptId: string): Promise<Receipt> {
    const text = (await this.request("GET", `/v1/receipts/${encodeURIComponent(receiptId)}`, { auth: false, text: true })) as string;
    const receipt = JSON.parse(text) as Receipt;
    RECEIPT_TEXT.set(receipt as object, text);
    return receipt;
  }

  /** Public by design: `/.well-known/poaw-keys.json` (SPEC §5.2, §8.4). */
  async getKeys(): Promise<Keyset> {
    return (await this.request("GET", "/.well-known/poaw-keys.json", { auth: false })) as Keyset;
  }

  /** The signed tree head and latest anchor. Public: no Authorization header. */
  async logHead(): Promise<LogHead> {
    return (await this.request("GET", "/v1/log/head", { auth: false })) as LogHead;
  }

  /** A consistency proof that the size-`first` tree is a prefix of the size-`second` tree. Public. */
  async logConsistency(first: number, second: number): Promise<LogConsistency> {
    assertIndex("first", first);
    assertIndex("second", second);
    return (await this.request("GET", `/v1/log/consistency?first=${first}&second=${second}`, { auth: false })) as LogConsistency;
  }

  /** An inclusion proof for `leafIndex` in the tree of `treeSize` (default: the current size). Public. */
  async logProof(leafIndex: number, treeSize?: number): Promise<LogInclusionProof> {
    assertIndex("leafIndex", leafIndex);
    let path = `/v1/log/proof?leaf_index=${leafIndex}`;
    if (treeSize !== undefined) {
      assertIndex("treeSize", treeSize);
      path += `&tree_size=${treeSize}`;
    }
    return (await this.request("GET", path, { auth: false })) as LogInclusionProof;
  }

  /** Landed anchors, newest first; page with `next` as `before`. Public. */
  async logAnchors(options: LogAnchorsOptions = {}): Promise<LogAnchorPage> {
    const query: Record<string, string> = {};
    if (options.limit !== undefined) query.limit = String(assertIndex("limit", options.limit));
    if (options.before !== undefined) query.before = String(assertIndex("before", options.before));
    const qs = new URLSearchParams(query).toString();
    return (await this.request("GET", `/v1/log/anchors${qs ? `?${qs}` : ""}`, { auth: false })) as LogAnchorPage;
  }

  /** The entry ledger (leaf hashes only), ascending from `start`; page with `next`. Public. */
  async logEntries(options: LogEntriesOptions = {}): Promise<LogEntryPage> {
    const query: Record<string, string> = {};
    if (options.start !== undefined) query.start = String(assertIndex("start", options.start));
    if (options.limit !== undefined) query.limit = String(assertIndex("limit", options.limit));
    const qs = new URLSearchParams(query).toString();
    return (await this.request("GET", `/v1/log/entries${qs ? `?${qs}` : ""}`, { auth: false })) as LogEntryPage;
  }

  async verify(
    receipt: unknown | string,
    options: { keys?: Keyset; rpcUrl?: string; consistency?: VerifyOptions["consistency"]; head?: unknown; nitroRoot?: VerifyOptions["nitroRoot"] } = {},
  ): Promise<VerifyReport> {
    const keys = options.keys ?? (await this.getKeys());
    // This client knows its issuer: an anchor at a different tree size is proven with that issuer's consistency proof.
    return verifyReceipt(receipt, {
      keys, rpcUrl: options.rpcUrl, consistency: options.consistency, head: options.head, nitroRoot: options.nitroRoot, issuer: this.baseUrl, fetch: this.fetchImpl,
    });
  }
}

function assertIndex(name: string, value: number): number {
  if (!Number.isInteger(value) || value < 0) throw new RangeError(`${name} must be a non-negative integer, got ${value}`);
  return value;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function cryptoRandomId(): string {
  const g = globalThis as {
    crypto?: {
      randomUUID?: () => string;
      getRandomValues?: <T extends ArrayBufferView | null>(array: T) => T;
    };
  };
  if (g.crypto?.randomUUID) return g.crypto.randomUUID();
  if (g.crypto?.getRandomValues) {
    const bytes = new Uint8Array(16);
    g.crypto.getRandomValues(bytes);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return `claim-${Date.now()}-${hex}`;
  }
  return `claim-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
