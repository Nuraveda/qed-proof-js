# @qed-proof/sdk

TypeScript SDK for [QED Proof](https://qedproof.site). Submit claims, poll for verdicts, and
verify PoAW receipts offline. Runs on Node ≥ 18, Deno and in browsers — only `fetch` and
Web-Crypto-free pure JS (`@noble/curves`, `@noble/hashes`, `canonicalize`), no Node built-ins.

## Install

```bash
npm install @qed-proof/sdk
```

## Submit a claim and check its receipt

```ts
import { QedProof, actions } from "@qed-proof/sdk";

const qp = new QedProof({ apiKey: process.env.QED_PROOF_API_KEY }); // or QED_PROOF_API_KEY env var

const claim = await qp.submitClaim(
  actions.githubCommitPush({ target: "owner/repo", sha: "…", branch: "main" }),
  { agentId: "my-agent", clientClaimId: "deploy-42" },
);
const decided = await qp.waitForVerdict(claim.claim_id, { timeoutMs: 120_000 });
const receipt = await qp.getReceipt(decided.receipt_id!); // no API key needed — receipts are public
const report = await qp.verify(receipt); // fetches keys itself, or pass { keys, rpcUrl }

console.log(report.valid, report.verdict, report.achieved_trust_level);
```

## List claims

```ts
const page = await qp.listClaims({ agentId: "my-agent" }); // newest first
for (const claim of page.claims) console.log(claim.claim_id, claim.state, claim.verdict);
page.nextCursor; // string, or null if this was the last page

// or walk every matching claim, following nextCursor automatically:
for await (const claim of qp.iterClaims({ agentId: "my-agent", action: "github.commit.push" })) {
  console.log(claim.claim_id, claim.verdict);
}
```

`limit` (1-200, default 50), `cursor`, `agentId`, `action`, `verdict` and `state` are all optional
filters on `listClaims`; an out-of-range `limit` throws a `RangeError` locally, before any request.
`iterClaims` takes the same filters plus `pageSize` (default 50).

## Verify a receipt you already have, fully offline

```ts
import { verifyReceipt } from "@qed-proof/sdk";

const keys = JSON.parse(await fetch("https://api.qedproof.site/.well-known/poaw-keys.json").then((r) => r.text()));
const report = await verifyReceipt(receiptJsonTextOrObject, { keys });
```

Pass the raw receipt JSON **text** (not just the parsed object) when you have it — it lets the
integers-only check (§3 of the spec) catch a float written as `1.0`, which is indistinguishable
from the integer `1` once `JSON.parse` has run. A genuinely non-integer value like `0.5` is
caught either way.

## Actions

`actions.githubCommitPush`, `githubPrOpen`, `githubChecksPass`, `xPostPublish`,
`slackMessagePost`, `httpUrlStatus` build a validated `{ action, target, params }` for
`submitClaim`, matching the wire shape in `oss/spec/profiles/*.md`.

## Errors

`QedProofError` (`status`, `detail`) and `RateLimitError` (adds `retryAfter`, read from
`Retry-After`). Error messages never include the API key.

## What's ported from the reference implementation

`verifyReceipt` ports `oss/spec/tools/check.py`, `oss/spec/tools/anchor_check.py` and the
primitives in `oss/core-python/src/poaw_core`: RFC 8785 JCS, Ed25519 signatures, the
`claim_digest`, RFC 6962 Merkle inclusion, JSON Schema validation (via `ajv`, draft 2020-12),
and the EAS anchor check over JSON-RPC with a small hand-written ABI decoder. It reproduces every
one of the 20 conformance vectors in `../../test/vectors/manifest.json` exactly.

At `trust_level` 3 it also verifies the receipt's AWS Nitro Enclaves attestation (`checks.attestation`): the COSE_Sign1
document, its certificate chain to the pinned AWS Nitro root, PCR0 = the receipt's `code_hash`, `user_data` = the statement
digest, and a build the issuer publishes in `verifier_builds`. Level 3 is reported as achieved only on top of level 2.

## License

Apache-2.0. See [LICENSE](LICENSE).
