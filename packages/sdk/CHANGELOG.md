# Changelog

All notable changes to `@qed-proof/sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-04

Adds trust level 3: verifying the AWS Nitro Enclaves attestation of a receipt (SPEC §7.1, §10 step 5).

### Added

- `verifyReceipt` checks the attestation when the body claims `trust_level` >= 3 and reports it as `checks.attestation` (`true`
  or the reason: `attestation_invalid`, `attestation_chain`, `pcr_mismatch`, `statement_mismatch`, `unknown_build`). Levels are
  cumulative: `achieved_trust_level` is 3 only when level 2 (inclusion + verified anchor) holds and the attestation verifies. A
  failed attestation never invalidates the receipt; it only keeps the achieved level lower. The issuer's `verifier_builds`
  (from its keyset) say which enclave builds are published.
- `verifyNitroAttestation`, `verifyEnclaveReceipt`, `attestationDocumentSha256`, `enclaveStatement`, `enclaveStatementDigest` and
  `AttestationError` are exported. The AWS Nitro root is pinned (SHA-256 `641a0321...bb5b`) and checked when the module loads.
- `verifyReceipt(..., { nitroRoot })` replaces the pinned root with another certificate. For tests only.

### Notes

- No new dependency: the CBOR and X.509 reading is a small strict implementation in the package (no `eval`, strict-CSP safe),
  and ECDSA P-384 uses `@noble/curves`, which the SDK already depends on. It does not need WebCrypto, so it also runs on Node 18.
  Only `ecdsa-with-SHA384` over P-384 certificates are accepted, as the AWS Nitro PKI uses.

## [0.3.0] - 2026-10-04

Adds the free public Merkle log: read the log and check signed tree heads and consistency proofs.

### Added

- `QedProof.logHead()`, `logConsistency(first, second)`, `logProof(leafIndex, treeSize?)`, `logAnchors({ limit, before })` and
  `logEntries({ start, limit })` for the free public Merkle log (`/v1/log/*`). No API key is sent. Response types are exported
  (`LogHead`, `LogConsistency`, `LogInclusionProof`, `LogAnchorPage`, `LogEntryPage`, ...).
- `verifyTreeHead(head, keys)` (SPEC §8.5) and `verifyConsistency(m, n, oldRoot, newRoot, proof)` (RFC 9162 §2.1.4.2), exported.
- `verifyReceipt(..., { head })` also checks a signed tree head and that the receipt's tree is a prefix of it (`checks.head`).

### Changed

- An anchor at a different tree size than the receipt's proof is now verified with a consistency proof instead of being
  refused. Pass `consistency` (a `/v1/log/consistency` response) to `verifyReceipt`, or `issuer` (a base URL; `QedProof.verify`
  uses its own) to fetch it. Without one the result is still `consistency_proof_required`.

## [0.2.0] - 2026-10-01

### Added

- `verifyReceipt` verifies **change entries** (`entry_kind: "change"`, SPEC §14): signed log entries for a change at a
  destination that no claim explained. They are signed under their own domain, so a signature on a change entry never
  verifies as a receipt, or the other way round. The report has `entry_kind: "change"`, no verdict and no `claim_digest`.
- `verifyReceipt(receipt, { keys, pipeline })`: pass the pipeline document to check a receipt's or change entry's `policy`
  (SPEC §15.2). The report gains `checks.policy`: `true`, `false`, or `"not_checked"` when no document is given. A failed
  policy check makes the entry invalid.
- `pipelineDigest(pipeline)`, `entryKind(body)`, `CHANGE_SIG_DOMAIN` and types for change entries and pipeline documents.

### Changed

- Accepts `poaw/0.1` and `poaw/0.2` receipts. Reports for receipts that use nothing new are unchanged.

## [0.1.6] - 2026-10-01

### Changed

- The source repository moved to `github.com/Nuraveda/qed-proof-js` (the old URL redirects). The
  package's `repository` field and provenance now point there. No code changes.

## [0.1.5] - 2026-09-28

### Changed

- `waitForVerdict` backs off exponentially (x2 per poll, capped at 30 s), matching the Python SDK. It still never sleeps past `timeoutMs` and still honours `Retry-After`.
- A generated `client_claim_id` uses `crypto.getRandomValues` when `crypto.randomUUID` is unavailable, before falling back to `Math.random`.

## [0.1.4] - 2026-09-28

### Fixed

- Works in browsers: `QedProof` now calls `fetch` as a plain function. 0.1.0–0.1.3 called it as a method of the client, which browsers reject with "Illegal invocation" (Node accepts it).

## [0.1.3] - 2026-09-28

Same code as 0.1.2. 0.1.2 was tagged but never published: the release job's npm was too old for trusted publishing.

## [0.1.2] - 2026-09-28 (never published)

### Fixed

- Works under a strict Content-Security-Policy (no `'unsafe-eval'`). The receipt schema is now precompiled at build time (ajv standalone), so importing the SDK no longer generates code with `new Function`; 0.1.1 threw at import in such pages. `ajv` and `ajv-formats` are no longer runtime dependencies.

## [0.1.1] - 2026-09-27

The first published version. 0.1.0 was tagged on the public repo but never published.

### Fixed

- `repository.directory` is now `packages/sdk` (it said `packages/packages`).

## [0.1.0] - 2026-09-27 (never published)

### Added

- `QedProof` client: `submitClaim`, `getClaim`, `waitForVerdict`, `listClaims`, `iterClaims`,
  `getReceipt`, `getKeys`, `verify`.
- `verifyReceipt`: a full port of `check.py` + `anchor_check.py` + `poaw_core`'s primitives
  (JCS, Ed25519, Merkle inclusion, JSON Schema validation, EAS anchor check over JSON-RPC).
- `actions.*` typed helpers for the five live actions plus `http.url.status`.
- `QedProofError`, `RateLimitError`.
- Types generated from the vendored `receipt.schema.json`.

[Unreleased]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.3.0...HEAD
[0.4.0]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.3.0...sdk-js-v0.4.0
[0.3.0]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.2.0...sdk-js-v0.3.0
[0.2.0]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.1.6...sdk-js-v0.2.0
[0.1.6]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.1.5...sdk-js-v0.1.6
[0.1.5]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.1.4...sdk-js-v0.1.5
[0.1.4]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.1.3...sdk-js-v0.1.4
[0.1.3]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.1.2...sdk-js-v0.1.3
[0.1.2]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.1.1...sdk-js-v0.1.2
[0.1.1]: https://github.com/Nuraveda/qed-proof-js/compare/sdk-js-v0.1.0...sdk-js-v0.1.1
[0.1.0]: https://github.com/Nuraveda/qed-proof-js/releases/tag/sdk-js-v0.1.0
