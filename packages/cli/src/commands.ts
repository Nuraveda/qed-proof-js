import { readFileSync } from "node:fs";
import { QedProof, actions, verifyReceipt, verifyTreeHead, type ClaimAction } from "@qed-proof/sdk";
import { readConfig, writeConfig, clearConfig, resolveApiKey, resolveBaseUrl, maskKey } from "./config.js";
import { promptHidden, readStdinAll } from "./prompt.js";
import type { Io } from "./io.js";

export interface GlobalFlags {
  json?: boolean;
}

function client(fetchImpl?: typeof fetch): QedProof {
  const config = readConfig();
  const apiKey = resolveApiKey(config);
  const baseUrl = resolveBaseUrl(config);
  return new QedProof({ apiKey, baseUrl, fetch: fetchImpl });
}

export interface LoginDeps {
  promptHidden: typeof promptHidden;
  readStdinAll: typeof readStdinAll;
}

const defaultLoginDeps: LoginDeps = { promptHidden, readStdinAll };

export async function login(
  args: { keyStdin?: boolean; baseUrl?: string },
  io: Io,
  deps: LoginDeps = defaultLoginDeps,
): Promise<number> {
  let apiKey: string;
  if (args.keyStdin) {
    apiKey = await deps.readStdinAll();
  } else {
    apiKey = await deps.promptHidden("API key: ");
  }
  if (!apiKey) {
    io.error("qed login: no API key provided");
    return 1;
  }
  const existing = readConfig();
  writeConfig({ apiKey, baseUrl: args.baseUrl ?? existing.baseUrl });
  io.log(`Logged in. API key ending in ${maskKey(apiKey)} saved.`);
  return 0;
}

export async function logout(io: Io): Promise<number> {
  clearConfig();
  io.log("Logged out.");
  return 0;
}

function buildAction(actionName: string, target: string, params: Record<string, string>): ClaimAction {
  switch (actionName) {
    case "github.commit.push":
      return actions.githubCommitPush({ target, sha: params.sha, branch: params.branch });
    case "github.pr.open":
      return actions.githubPrOpen({
        target,
        number: Number(params.number),
        base: params.base,
        headSha: params.head_sha ?? params.headSha,
      });
    case "github.checks.pass":
      return actions.githubChecksPass({ target, sha: params.sha });
    case "x.post.publish":
      return actions.xPostPublish({ target, postId: params.post_id ?? params.postId, textSha256: params.text_sha256 ?? params.textSha256 });
    case "slack.message.post":
      return actions.slackMessagePost({ target, ts: params.ts, textSha256: params.text_sha256 ?? params.textSha256 });
    case "http.url.status":
      return actions.httpUrlStatus({
        target,
        status: params.status !== undefined ? Number(params.status) : undefined,
        contentFingerprint: params.content_fingerprint ?? params.contentFingerprint,
      });
    default:
      // Unknown/future actions: pass params through as given (still validated server-side).
      return { action: actionName, target, params };
  }
}

export interface ClaimArgs {
  action: string;
  target: string;
  param: string[];
  agent?: string;
  id?: string;
  wait?: boolean;
  json?: boolean;
}

export function parseParams(pairs: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx < 0) throw new TypeError(`--param must be key=value, got: ${pair}`);
    out[pair.slice(0, idx)] = pair.slice(idx + 1);
  }
  return out;
}

export async function claim(args: ClaimArgs, io: Io, fetchImpl?: typeof fetch): Promise<number> {
  const params = parseParams(args.param ?? []);
  const built = buildAction(args.action, args.target, params);
  const qp = client(fetchImpl);
  const result = await qp.submitClaim(built, {
    agentId: args.agent ?? "qed-cli",
    clientClaimId: args.id,
  });
  let final = result;
  if (args.wait) {
    final = await qp.waitForVerdict(result.claim_id);
  }
  if (args.json) {
    io.log(JSON.stringify(final, null, 2));
  } else {
    io.log(`claim ${final.claim_id}: state=${final.state} attempts=${final.attempts} receipt_id=${final.receipt_id ?? "-"} verdict=${final.verdict ?? "-"}`);
  }
  return 0;
}

export interface ClaimsListArgs {
  limit?: number;
  agent?: string;
  action?: string;
  verdict?: string;
  state?: string;
  all?: boolean;
  json?: boolean;
}

function padCol(value: string, width: number): string {
  return value.length >= width ? value : value + " ".repeat(width - value.length);
}

function printClaimsTable(claims: Array<{ claim_id: string; state: string; verdict: string | null; receipt_id: string | null }>, io: Io): void {
  const idW = Math.max(8, ...claims.map((c) => c.claim_id.length));
  const stateW = Math.max(5, ...claims.map((c) => c.state.length));
  const verdictW = Math.max(7, ...claims.map((c) => (c.verdict ?? "-").length));
  for (const c of claims) {
    io.log(`${padCol(c.claim_id, idW)}  ${padCol(c.state, stateW)}  ${padCol(c.verdict ?? "-", verdictW)}  ${c.receipt_id ?? "-"}`);
  }
}

export async function claimsList(args: ClaimsListArgs, io: Io, fetchImpl?: typeof fetch): Promise<number> {
  const qp = client(fetchImpl);
  const filters = { agentId: args.agent, action: args.action, verdict: args.verdict, state: args.state };
  const claims: Array<{ claim_id: string; state: string; verdict: string | null; receipt_id: string | null }> = [];
  if (args.all) {
    for await (const claim of qp.iterClaims({ ...filters, pageSize: args.limit })) {
      claims.push(claim);
    }
  } else {
    const page = await qp.listClaims({ ...filters, limit: args.limit });
    claims.push(...page.claims);
  }
  if (args.json) {
    io.log(JSON.stringify(claims, null, 2));
  } else if (claims.length === 0) {
    io.log("no claims found");
  } else {
    printClaimsTable(claims, io);
  }
  return 0;
}

export async function receiptsGet(args: { id: string; json?: boolean }, io: Io): Promise<number> {
  const qp = client();
  const receipt = await qp.getReceipt(args.id);
  io.log(JSON.stringify(receipt, null, 2));
  return 0;
}

export async function watch(args: { claimId: string; json?: boolean }, io: Io): Promise<number> {
  const qp = client();
  const status = await qp.waitForVerdict(args.claimId);
  if (args.json) {
    io.log(JSON.stringify(status, null, 2));
  } else {
    io.log(`claim ${status.claim_id} decided: verdict=${status.verdict ?? "-"} receipt_id=${status.receipt_id ?? "-"}`);
  }
  return 0;
}

async function loadReceiptText(source: string): Promise<string> {
  if (source.startsWith("http://") || source.startsWith("https://")) {
    const res = await fetch(source);
    if (!res.ok) throw new Error(`could not fetch receipt: HTTP ${res.status}`);
    return res.text();
  }
  return readFileSync(source, "utf-8");
}

async function loadKeys(source: string | undefined): Promise<unknown> {
  if (!source) {
    const qp = client();
    return qp.getKeys();
  }
  if (source.startsWith("http://") || source.startsWith("https://")) {
    const res = await fetch(source);
    if (!res.ok) throw new Error(`could not fetch keys: HTTP ${res.status}`);
    return res.json();
  }
  return JSON.parse(readFileSync(source, "utf-8"));
}

async function loadJson(source: string, what: string): Promise<unknown> {
  if (source.startsWith("http://") || source.startsWith("https://")) {
    const res = await fetch(source);
    if (!res.ok) throw new Error(`could not fetch ${what}: HTTP ${res.status}`);
    return res.json();
  }
  return JSON.parse(readFileSync(source, "utf-8"));
}

export async function verify(
  args: {
    file: string;
    keys?: string;
    rpc?: string;
    pipeline?: string;
    head?: string;
    consistency?: string[];
    issuer?: string;
    /** TESTS ONLY: a PEM or DER certificate to trust as the attestation root instead of the AWS Nitro root. */
    nitroRoot?: string;
    json?: boolean;
  },
  io: Io,
): Promise<number> {
  const receiptText = await loadReceiptText(args.file);
  const keys = (await loadKeys(args.keys)) as Parameters<typeof verifyReceipt>[1]["keys"];
  // The pipeline document lets the checker confirm the entry's `policy` (SPEC §15.2). Without it, policy is "not_checked".
  const pipeline = args.pipeline ? JSON.parse(readFileSync(args.pipeline, "utf-8")) : undefined;
  // Same semantics as oss/spec/tools/check.py: --head is a file or the issuer's /v1/log/head URL (which also names the
  // issuer), --consistency files are /v1/log/consistency responses, --issuer fetches a missing proof (SPEC §8.4-§8.5).
  let issuer = args.issuer;
  let head: unknown;
  if (args.head) {
    head = await loadJson(args.head, "tree head");
    const url = args.head.replace(/\/+$/, "");
    if (!issuer && /^https?:\/\//.test(url) && url.endsWith("/v1/log/head")) issuer = url.slice(0, -"/v1/log/head".length);
  }
  const consistency = await Promise.all((args.consistency ?? []).map((f) => loadJson(f, "consistency proof")));
  // --nitro-root: a trust-anchor override for tests, as in check.py. A PEM file is passed as text, anything else as DER.
  let nitroRoot: string | Uint8Array | undefined;
  if (args.nitroRoot) {
    const raw = readFileSync(args.nitroRoot);
    nitroRoot = raw.toString("latin1").trimStart().startsWith("-----BEGIN") ? raw.toString("utf-8") : new Uint8Array(raw);
  }
  const report = await verifyReceipt(receiptText, {
    keys,
    rpcUrl: args.rpc,
    pipeline,
    head,
    issuer,
    nitroRoot,
    consistency: consistency.length > 0 ? (consistency as Parameters<typeof verifyReceipt>[1]["consistency"]) : undefined,
  });

  if (args.json) {
    io.log(JSON.stringify(report, null, 2));
  } else {
    if (report.entry_kind) io.log(`kind:       ${report.entry_kind} entry (an unclaimed change, not a receipt)`);
    io.log(`signature:  ${report.checks.signature}`);
    io.log(`inclusion:  ${report.checks.inclusion}`);
    io.log(`anchor:     ${report.checks.anchor}`);
    io.log(`attestation: ${report.checks.attestation === undefined ? "not applicable" : report.checks.attestation}`);
    if (report.checks.policy !== undefined) io.log(`policy:     ${report.checks.policy}`);
    if (report.checks.head !== undefined) io.log(`head:       ${report.checks.head}`);
    io.log(`verdict:    ${report.verdict ?? "-"}`);
    io.log(`valid:      ${report.valid}`);
    io.log(`trust level achieved: ${report.achieved_trust_level}`);
  }
  return report.valid ? 0 : 1;
}

/**
 * `qed log head [--verify]`: the issuer's signed tree head. The log is public, so no API key is sent. With `--verify` the
 * head's signature is checked against `/.well-known/poaw-keys.json` (or `--keys`); exit 1 when it does not verify.
 */
export async function logHead(args: { verify?: boolean; keys?: string; json?: boolean }, io: Io, fetchImpl?: typeof fetch): Promise<number> {
  const qp = client(fetchImpl);
  const head = await qp.logHead();
  const body = head.tree_head.body;
  const sig = head.tree_head.signature;
  let report: ReturnType<typeof verifyTreeHead> | undefined;
  if (args.verify) {
    const keys = args.keys ? await loadKeys(args.keys) : await qp.getKeys();
    report = verifyTreeHead(head, keys as Parameters<typeof verifyTreeHead>[1]);
  }
  if (args.json) {
    io.log(JSON.stringify(report ? { ...head, verification: report } : head, null, 2));
  } else {
    io.log(`log:        ${body.log_id}`);
    io.log(`size:       ${body.tree_size}`);
    io.log(`root:       ${body.root_hash}`);
    io.log(`issued at:  ${body.issued_at}`);
    io.log(`key id:     ${sig.key_id}`);
    if (head.anchor) {
      io.log(`anchor:     ${head.anchor.chain} tx ${head.anchor.tx_hash} (tree size ${head.anchor.tree_size}, block ${head.anchor.block_number})`);
    } else {
      io.log("anchor:     none yet");
    }
    io.log(`signature:  ${report ? (report.valid ? "valid" : "INVALID") : "not checked (use --verify)"}`);
  }
  return report && !report.valid ? 1 : 0;
}
