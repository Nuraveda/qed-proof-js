import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TREE_HEAD_SIG_DOMAIN, b64u, b64uDecode, jcs, keyId } from "@qed-proof/sdk";
import { writeConfig } from "../src/config.js";
import { logHead, verify } from "../src/commands.js";
import type { Io } from "../src/io.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, "..", "..", "..", "test", "vectors");
const v = (f: string) => join(vectors, f);
const keysFile = v("keys.json");

function captureIo(): { io: Io; lines: string[] } {
  const lines: string[] = [];
  return { io: { log: (l) => lines.push(l), error: (l) => lines.push(l) }, lines };
}
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
const readJson = async (f: string) => JSON.parse((await import("node:fs")).readFileSync(f, "utf-8"));

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "qed-cli-log-test-"));
  process.env.QED_PROOF_CONFIG_DIR = dir;
  writeConfig({ apiKey: "qed_sk_secret", baseUrl: "https://api.example.test" });
});
afterEach(() => {
  delete process.env.QED_PROOF_CONFIG_DIR;
  rmSync(dir, { recursive: true, force: true });
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("qed log head", () => {
  async function run(headFile: string, verifyFlag: boolean, extra: { json?: boolean; keys?: string } = {}) {
    const head = { tree_head: await readJson(v(headFile)), anchor: { chain: "base-sepolia", scheme: "eas", uid: "0xu", tx_hash: "0xabc", tree_size: 7, root_hash: "r", block_number: 42, block_time: "t" } };
    const keys = await readJson(keysFile);
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const f = vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      return url.endsWith("/v1/log/head") ? json(head) : json(keys);
    });
    const { io, lines } = captureIo();
    const code = await logHead({ verify: verifyFlag, ...extra }, io, f as unknown as typeof fetch);
    return { code, lines, calls };
  }

  it("prints size, root, key id and anchor, sends no API key, and verifies the signature", async () => {
    const { code, lines, calls } = await run("036-tree-head-valid.json", true);
    expect(code).toBe(0);
    expect(lines).toContain("size:       7");
    expect(lines.some((l) => l.startsWith("root:       i1xW"))).toBe(true);
    expect(lines.some((l) => l.startsWith("key id:     ed25519:"))).toBe(true);
    expect(lines.find((l) => l.startsWith("anchor:"))).toContain("0xabc");
    expect(lines).toContain("signature:  valid");
    expect(calls.map((c) => c.url)).toEqual(["https://api.example.test/v1/log/head", "https://api.example.test/.well-known/poaw-keys.json"]);
    for (const c of calls) expect((c.init?.headers as Record<string, string>).authorization).toBeUndefined();
  });

  it("exits 1 on a tampered head with --verify; without it, reports not checked and fetches no keys", async () => {
    const bad = await run("037-tree-head-tampered.json", true);
    expect(bad.code).toBe(1);
    expect(bad.lines).toContain("signature:  INVALID");
    const plain = await run("037-tree-head-tampered.json", false);
    expect(plain.code).toBe(0);
    expect(plain.calls).toHaveLength(1);
    expect(plain.lines.find((l) => l.startsWith("signature:"))).toContain("not checked");
  });

  it("--json includes the verification report", async () => {
    const { lines } = await run("036-tree-head-valid.json", true, { json: true });
    expect(JSON.parse(lines.join("\n")).verification.valid).toBe(true);
  });
});

describe("qed verify --head / --consistency / --issuer", () => {
  it("a validly signed head over the receipt's own tree passes and prints head: true; another root fails", async () => {
    // The vector heads sign a different tree than the vector receipts, so sign a head over 016's tree with a fresh key.
    const receipt = await readJson(v("016-inclusion-first-leaf.json"));
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pub = b64uDecode(publicKey.export({ format: "jwk" }).x as string);
    const kid = keyId(pub);
    const keys = { keys: [{ key_id: kid, public_key: b64u(pub), valid_from: "2026-01-01T00:00:00.000Z", revoked_at: null }] };
    const signed = (root: string) => {
      const body = { log_id: receipt.proof.log_id, tree_size: receipt.proof.tree_size, root_hash: root, issued_at: "2026-10-04T00:00:00.000Z" };
      const msg = Buffer.concat([TREE_HEAD_SIG_DOMAIN, jcs(body)]);
      return { body, signature: { alg: "Ed25519", key_id: kid, value: b64u(sign(null, msg, privateKey)) } };
    };
    const keysFile2 = join(dir, "keys.json");
    // The receipt itself is signed by the vector key, so the keyset must hold both keys.
    const vectorKeys = await readJson(keysFile);
    writeFileSync(keysFile2, JSON.stringify({ keys: [...vectorKeys.keys, ...keys.keys] }));
    const headOk = join(dir, "head-ok.json");
    writeFileSync(headOk, JSON.stringify(signed(receipt.proof.root_hash)));
    const ok = captureIo();
    expect(await verify({ file: v("016-inclusion-first-leaf.json"), keys: keysFile2, head: headOk }, ok.io)).toBe(0);
    expect(ok.lines).toContain("head:       true");
    const headBad = join(dir, "head-bad.json");
    writeFileSync(headBad, JSON.stringify(signed(receipt.proof.root_hash.replace(/^./, "A"))));
    const bad = captureIo();
    expect(await verify({ file: v("016-inclusion-first-leaf.json"), keys: keysFile2, head: headBad }, bad.io)).toBe(1);
    expect(bad.lines).toContain("head:       root_mismatch");
  });

  it("a tampered head fails the receipt", async () => {
    const { io, lines } = captureIo();
    const code = await verify({ file: v("016-inclusion-first-leaf.json"), keys: keysFile, head: v("037-tree-head-tampered.json") }, io);
    expect(code).toBe(1);
    expect(lines).toContain("head:       head_signature_invalid");
  });

  it("a head with a larger tree needs a consistency proof; a head URL names the issuer to fetch it from", async () => {
    // vector 034's tree has 5 leaves, the head has 7.
    const none = captureIo();
    expect(await verify({ file: v("034-change-inclusion.json"), keys: keysFile, pipeline: v("pipeline.example.json"), head: v("036-tree-head-valid.json") }, none.io)).toBe(1);
    expect(none.lines).toContain("head:       consistency_proof_required");

    const head = await readJson(v("036-tree-head-valid.json"));
    const f = vi.fn(async (url: string) => (url.endsWith("/v1/log/head") ? json(head) : json({ detail: "nope" }, 404)));
    vi.stubGlobal("fetch", f);
    const { io, lines } = captureIo();
    const code = await verify(
      { file: v("034-change-inclusion.json"), keys: keysFile, pipeline: v("pipeline.example.json"), head: "https://issuer.example.test/v1/log/head" },
      io,
    );
    expect(code).toBe(1);
    expect(lines).toContain("head:       consistency_proof_required");
    expect(f.mock.calls.map((c) => c[0])).toContain("https://issuer.example.test/v1/log/consistency?first=5&second=7");
  });

  it("--consistency files are accepted (a proof for other sizes does not help)", async () => {
    const { io, lines } = captureIo();
    const code = await verify(
      { file: v("034-change-inclusion.json"), keys: keysFile, pipeline: v("pipeline.example.json"), head: v("036-tree-head-valid.json"), consistency: [v("040-consistency-valid.json")] },
      io,
    );
    expect(code).toBe(1);
    expect(lines).toContain("head:       consistency_proof_required");
  });
});
