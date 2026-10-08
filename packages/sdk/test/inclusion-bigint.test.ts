/** Audit #252: inclusion verification must stay exact beyond 2^31, where JavaScript's `>>` and `&` wrap to 32 bits. */
import { describe, expect, it } from "vitest";
import { rootFromInclusion, sha256 } from "../src/primitives.js";

const leaf = sha256(new TextEncoder().encode("leaf"));
const sibling = sha256(new TextEncoder().encode("sibling"));

describe("rootFromInclusion beyond 32 bits", () => {
  it("accepts a one-sibling path only for a tree of two leaves", () => {
    expect(rootFromInclusion(0, 2, leaf, [sibling])).not.toBeNull();
  });

  it("rejects the same truncated path for a tree of 2^32 + 2 leaves", () => {
    // With 32-bit shifts, 4294967297 (size - 1) wraps and the loop ends as if the tree had two leaves.
    expect(rootFromInclusion(0, 4294967298, leaf, [sibling])).toBeNull();
  });

  it("rejects indices and sizes that aren't safe integers", () => {
    expect(rootFromInclusion(0, Number.MAX_SAFE_INTEGER + 2, leaf, [sibling])).toBeNull();
    expect(rootFromInclusion(-1, 2, leaf, [sibling])).toBeNull();
    expect(rootFromInclusion(0.5, 2, leaf, [sibling])).toBeNull();
  });
});
