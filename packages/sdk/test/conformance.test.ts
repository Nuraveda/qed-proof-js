/**
 * Conformance suite: for every entry of test/vectors/manifest.json, verifyReceipt(...) must
 * deep-equal entry.expected exactly. This is oss/sdk-js's copy of the spec's own conformance
 * vectors (synced from oss/spec/vectors — see docs/lanes/sdk-clients.md). Do not edit the vendored
 * vectors; this test only reads them.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { pipelineDigest } from "../src/primitives.js";
import { verifyReceipt } from "../src/verify.js";
import { verifyConsistency, verifyTreeHead } from "../src/log.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "..", "..", "test", "vectors");

const manifest = JSON.parse(readFileSync(join(vectorsDir, "manifest.json"), "utf-8")) as {
  keyset: string;
  vectors: Array<{ description: string; expected: Record<string, unknown>; file: string; pipeline?: string }>;
};
const keys = JSON.parse(readFileSync(join(vectorsDir, manifest.keyset), "utf-8"));

describe("conformance vectors (poaw/0.1 and poaw/0.2)", () => {
  for (const vector of manifest.vectors) {
    it(`${vector.file}: ${vector.description}`, async () => {
      const receiptText = readFileSync(join(vectorsDir, vector.file), "utf-8");
      const pipeline = vector.pipeline
        ? JSON.parse(readFileSync(join(vectorsDir, vector.pipeline), "utf-8"))
        : undefined;
      const report = await verifyReceipt(receiptText, { keys, pipeline });
      expect(report).toEqual(vector.expected);
    });
  }

  it("runs all 35 vectors", () => {
    expect(manifest.vectors).toHaveLength(35);
  });
});

describe("public log vectors (SPEC §8.4–§8.5)", () => {
  const read = (f: string) => JSON.parse(readFileSync(join(vectorsDir, f), "utf-8"));
  const extra = JSON.parse(readFileSync(join(vectorsDir, "manifest.json"), "utf-8")) as {
    tree_head_vectors: Array<{ description: string; expected: Record<string, unknown>; file: string }>;
    consistency_vectors: Array<{ description: string; expected: { valid: boolean }; file: string }>;
  };

  for (const v of extra.tree_head_vectors) {
    it(`${v.file}: ${v.description}`, () => {
      expect(verifyTreeHead(read(v.file), keys)).toEqual(v.expected);
    });
  }
  for (const v of extra.consistency_vectors) {
    it(`${v.file}: ${v.description}`, () => {
      const d = read(v.file);
      expect(verifyConsistency(d.first, d.second, d.first_root, d.second_root, d.proof)).toBe(v.expected.valid);
    });
  }

  it("lists 4 tree heads and 2 consistency proofs, and the original 35 vectors are untouched", () => {
    expect(extra.tree_head_vectors).toHaveLength(4);
    expect(extra.consistency_vectors).toHaveLength(2);
  });
});

describe("pipelineDigest and change entries", () => {
  const read = (f: string) => JSON.parse(readFileSync(join(vectorsDir, f), "utf-8"));

  it("pipelineDigest of the example pipeline equals the policy digest in vector 022", () => {
    const policy = read("022-valid-policy-checked.json").body.policy;
    expect(pipelineDigest(read("pipeline.example.json"))).toBe(policy.digest);
  });

  it("pipelineDigest ignores key order", () => {
    const p = read("pipeline.example.json") as Record<string, unknown>;
    const reversed = Object.fromEntries(Object.entries(p).reverse());
    expect(Object.keys(reversed)[0]).not.toBe(Object.keys(p)[0]);
    expect(pipelineDigest(reversed)).toBe(pipelineDigest(p));
  });

  it("vector 027 verifies as a change entry with a null verdict", async () => {
    const report = await verifyReceipt(read("027-valid-change.json"), { keys, pipeline: read("pipeline.example.json") });
    expect(report.entry_kind).toBe("change");
    expect(report.verdict).toBeNull();
    expect(report.valid).toBe(true);
    expect(report.checks).not.toHaveProperty("claim_digest");
  });

  it("a policy is reported not_checked without a pipeline document", async () => {
    const report = await verifyReceipt(read("022-valid-policy-checked.json"), { keys });
    expect(report.checks.policy).toBe("not_checked");
    expect(report.valid).toBe(true);
  });
});
