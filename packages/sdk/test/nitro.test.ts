/**
 * Trust level 3 (SPEC §7.1): attestation vectors 042-048, the real AWS document, cumulative levels, and the CBOR decoder.
 * Ported from oss/core-python/tests/test_nitro.py.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { b64u, leafHash } from "../src/primitives.js";
import {
  AttestationError,
  CborMap,
  NITRO_ROOT_DER,
  NITRO_ROOT_SHA256,
  attestationDocumentSha256,
  cborDecode,
  verifyEnclaveReceipt,
  verifyNitroAttestation,
} from "../src/nitro.js";
import { verifyReceipt } from "../src/verify.js";

vi.mock("../src/anchor.js", async (orig) => {
  const real = (await orig()) as Record<string, unknown>;
  return { ...real, checkAnchor: vi.fn(async () => ({ ok: true, reason: "verified", proven_by: 2 })) };
});
import * as anchorModule from "../src/anchor.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "..", "..", "test", "vectors");
const readJson = (p: string) => JSON.parse(readFileSync(p, "utf-8"));
const manifest = readJson(join(vectorsDir, "manifest.json")) as {
  attestation_vectors: Array<{ description: string; expected: Record<string, unknown>; file: string; keyset: string; nitro_root: string }>;
};
const fixture = readJson(join(here, "fixtures", "nitro-live-build2.json")) as { attestation: string; expected_pcr0: string };
const testRoot = readFileSync(join(vectorsDir, "nitro-test-root.pem"), "utf-8");
const keysL3 = readJson(join(vectorsDir, "keys-l3.json"));
const h = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));

describe("attestation vectors 042-048 (SPEC §7.1)", () => {
  for (const v of manifest.attestation_vectors) {
    it(`${v.file}: ${v.description}`, async () => {
      const text = readFileSync(join(vectorsDir, v.file), "utf-8");
      const keys = readJson(join(vectorsDir, v.keyset));
      const root = readFileSync(join(vectorsDir, v.nitro_root), "utf-8");
      expect(await verifyReceipt(text, { keys, nitroRoot: root })).toEqual(v.expected);
    });
  }

  it("lists exactly seven attestation vectors", () => {
    expect(manifest.attestation_vectors.map((v) => v.file.slice(0, 3))).toEqual(["042", "043", "044", "045", "046", "047", "048"]);
  });

  it("without the test root the real AWS root is trusted, so a test chain is attestation_chain", async () => {
    const r = await verifyReceipt(readFileSync(join(vectorsDir, "042-l3-valid.json"), "utf-8"), { keys: keysL3 });
    expect(r.checks.attestation).toBe("attestation_chain");
    expect(r.achieved_trust_level).toBe(1);
    expect(r.valid).toBe(true);
  });
});

describe("the pinned root", () => {
  it("is the AWS Nitro G1 root and matches its SHA-256 fingerprint", async () => {
    const d = await crypto.subtle.digest("SHA-256", NITRO_ROOT_DER);
    expect(Buffer.from(d).toString("hex")).toBe(NITRO_ROOT_SHA256);
  });
});

describe("a real AWS Nitro document (enclave build 2, 2026-10-04)", () => {
  it("verifies against the pinned root at its own timestamp; PCR0 is the expected build", () => {
    const att = verifyNitroAttestation(fixture.attestation);
    expect(Buffer.from(att.pcrs.get(0)!).toString("hex")).toBe(fixture.expected_pcr0);
    expect(att.digest).toBe("SHA384");
    expect(att.userData).toHaveLength(32);
  });

  it("fails against any other root, and when the signature is altered", () => {
    expect(() => verifyNitroAttestation(fixture.attestation, { nitroRoot: testRoot })).toThrowError(/attestation_chain/);
    const raw = Uint8Array.from(Buffer.from(fixture.attestation, "base64url"));
    raw[raw.length - 5] ^= 1; // inside the COSE signature
    expect(() => verifyNitroAttestation(b64u(raw))).toThrowError(/attestation_invalid/);
  });

  it("is rejected outside the validity window of its certificates", () => {
    const att = verifyNitroAttestation(fixture.attestation);
    const day = 86_400_000;
    expect(() => verifyNitroAttestation(fixture.attestation, { at: att.timestamp - 40 * 365 * day })).toThrowError(/attestation_chain/);
    expect(() => verifyNitroAttestation(fixture.attestation, { at: att.timestamp + 40 * 365 * day })).toThrowError(/attestation_chain/);
  });
});

describe("cumulative trust levels", () => {
  const base = readJson(join(vectorsDir, "042-l3-valid.json"));
  // A one-leaf log: the leaf hash is the root, so inclusion verifies. The proof is outside the signed body.
  const withProof = () => {
    const root = b64u(leafHash({ body: base.body, signature: base.signature }));
    return { ...base, proof: { log_id: "dGVzdA", leaf_index: 0, tree_size: 1, root_hash: root, inclusion: [], anchor: { chain: "base", scheme: "eas", uid: "0x" + "ab".repeat(32), tx_hash: "0x" + "cd".repeat(32), tree_size: 1 } } };
  };
  const opts = { keys: keysL3, nitroRoot: testRoot, rpcUrl: "http://rpc.invalid" };

  it("achieved level 3 only with inclusion + a verified anchor AND a valid attestation", async () => {
    const r = await verifyReceipt(withProof(), opts);
    expect(r.checks).toMatchObject({ inclusion: true, anchor: true, attestation: true });
    expect(r.achieved_trust_level).toBe(3);
  });

  it("an anchor that does not verify keeps the receipt below level 2", async () => {
    vi.mocked(anchorModule.checkAnchor).mockResolvedValueOnce({ ok: false, reason: "anchor_missing", proven_by: null });
    const r = await verifyReceipt(withProof(), opts);
    expect(r.checks.attestation).toBe(true);
    expect(r.achieved_trust_level).toBe(1);
  });

  it("a good anchor with a bad attestation stays at level 2", async () => {
    const r = await verifyReceipt(withProof(), { ...opts, nitroRoot: undefined });
    expect(r.checks.attestation).toBe("attestation_chain");
    expect(r.achieved_trust_level).toBe(2);
  });
});

describe("receipt-level rules", () => {
  const base = readJson(join(vectorsDir, "042-l3-valid.json"));
  const builds = keysL3.verifier_builds;
  const clone = () => structuredClone(base);
  const reason = (rc: unknown, b: unknown = builds): string | true => {
    try {
      verifyEnclaveReceipt(rc, b as never, { nitroRoot: testRoot });
      return true;
    } catch (e) {
      if (e instanceof AttestationError) return e.reason;
      throw e;
    }
  };

  it("verifies the valid receipt", () => expect(reason(base)).toBe(true));
  it("a tampered document is attestation_invalid (hash mismatch, then payload)", () => {
    const rc = clone();
    rc.attestation_document = rc.attestation_document.slice(0, -4) + "AAAA";
    expect(reason(rc)).toBe("attestation_invalid");
    expect(reason({ ...clone(), attestation_document: "!!!" })).toBe("attestation_invalid");
  });
  it("document missing, type wrong, attestation absent", () => {
    const noDoc = clone();
    delete noDoc.attestation_document;
    expect(reason(noDoc)).toBe("attestation_invalid");
    const other = clone();
    other.body.attestation.type = "other";
    expect(reason(other)).toBe("attestation_invalid");
    const none = clone();
    delete none.body.attestation;
    expect(reason(none)).toBe("attestation_invalid");
  });
  it("a body that lacks statement fields is attestation_invalid, a changed verdict is statement_mismatch", () => {
    const rc = clone();
    delete rc.body.observation.facts;
    expect(reason(rc)).toBe("attestation_invalid");
    const v = clone();
    v.body.verdict.value = v.body.verdict.value === "verified" ? "failed" : "verified";
    expect(reason(v)).toBe("statement_mismatch");
  });
  it("an empty or unrelated verifier_builds list is unknown_build", () => {
    expect(reason(base, [])).toBe("unknown_build");
    expect(reason(base, null)).toBe("unknown_build");
  });
  it("the document hash helper is base64url SHA-256 of the raw bytes", () => {
    expect(attestationDocumentSha256(base.attestation_document)).toBe(base.body.attestation.document_sha256);
  });
});

describe("CBOR decoder", () => {
  it("decodes definite and indefinite items", () => {
    const m = cborDecode(h("bf616101616202ff")) as CborMap;
    expect([m.get("a"), m.get("b")]).toEqual([1, 2]);
    expect(cborDecode(h("9f0102ff"))).toEqual([1, 2]);
    expect(cborDecode(h("5f4201024103ff"))).toEqual(h("010203"));
    expect(cborDecode(h("7f61616162ff"))).toBe("ab");
    expect(cborDecode(h("20"))).toBe(-1);
    expect(cborDecode(h("f6"))).toBeNull();
    expect(cborDecode(h("f5"))).toBe(true);
  });
  it.each([
    ["bf6161", "no break"],
    ["ff", "lone break"],
    ["bf616101616101ff", "duplicate key (indefinite)"],
    ["a2616101616101", "duplicate key"],
    ["5f6161ff", "mixed chunk"],
    ["5f5f4101ffff", "nested indefinite chunk"],
    ["fa3fc00000", "float"],
    ["f7", "undefined"],
    ["c101", "tag"],
    ["0101", "trailing bytes"],
    ["4301", "truncated string"],
    ["8201", "truncated array"],
    ["1c", "reserved additional info"],
    ["62c328", "invalid utf-8"],
    ["a1f6f6", "null key"],
    ["a1f401", "boolean key"],
  ])("rejects %s (%s)", (hex) => {
    expect(() => cborDecode(h(hex))).toThrow();
  });
  it("rejects excessive nesting", () => {
    expect(() => cborDecode(h("81".repeat(20) + "00"))).toThrow();
  });
  it("garbage documents are attestation_invalid, never a crash", () => {
    for (const doc of ["", "AAAA", b64u(h("d2"))]) expect(() => verifyNitroAttestation(doc)).toThrowError(AttestationError);
  });
});
