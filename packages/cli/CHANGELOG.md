# Changelog

All notable changes to `@qed-proof/cli` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-04

### Added

- `qed verify` prints an `attestation:` line (`true`, the reason it failed, or `not applicable` below trust level 3) and
  accepts `--nitro-root <file>` (a PEM or DER certificate to trust instead of the AWS Nitro root; for tests only).

## [0.3.0] - 2026-10-04

Adds commands for the free public Merkle log.

### Added

- `qed verify <file> --head <file|url> [--consistency <file> ...] [--issuer <url>]` checks a receipt against a signed tree
  head and consistency proofs, like `check.py`. Prints a `head:` line.
- `qed log head [--verify]` prints the issuer's signed tree head (size, root, key id, anchor) and can verify its signature.

### Changed

- Needs `@qed-proof/sdk` 0.3.0.

## [0.2.0] - 2026-10-01

### Added

- `qed verify` prints what an entry is (a receipt, or a change entry for an unclaimed change) and its `policy` result.
- `qed verify <file> --pipeline <file>` checks the entry's policy against the pipeline document.

### Changed

- Needs `@qed-proof/sdk` 0.2.0.

## [0.1.6] - 2026-10-01

### Changed

- The source repository moved to `github.com/Nuraveda/qed-proof-js` (the old URL redirects). The
  package's `repository` field and provenance now point there. No code changes.

## [0.1.5] - 2026-09-28

### Changed

- Depends on `@qed-proof/sdk` 0.1.5. No CLI behaviour change.

## [0.1.4] - 2026-09-28

### Fixed

- Depends on `@qed-proof/sdk` 0.1.4. No CLI behaviour change.

## [0.1.3] - 2026-09-28

Same code as 0.1.2. 0.1.2 was tagged but never published: the release job's npm was too old for trusted publishing.

## [0.1.2] - 2026-09-28 (never published)

### Fixed

- Depends on `@qed-proof/sdk` 0.1.2 (CSP-safe schema validation). No CLI behaviour change.

## [0.1.1] - 2026-09-27

The first published version. 0.1.0 was tagged on the public repo but never published.

### Fixed

- The `qed` bin is kept on publish: npm 11 dropped `"./dist/cli.cjs"` as invalid, so 0.1.0 would have installed with no command. `repository.directory` is now `packages/cli`.

## [0.1.0] - 2026-09-27 (never published)

### Added

- `qed login` / `qed logout`, storing the API key at mode 0600 in the OS config dir.
- `qed claim`, `qed claims list` (`--all` follows the cursor), `qed receipts get`, `qed watch`.
- `qed verify`: offline receipt check, printing signature/inclusion/anchor/verdict/trust level
  and exiting 1 when the receipt is not valid.

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
