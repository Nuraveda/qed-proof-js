# @qed-proof/cli

`qed`: submit claims, watch verdicts and verify [QED Proof](https://qedproof.site) receipts from
the terminal. Built on [`@qed-proof/sdk`](../sdk).

## Install

```bash
npm install -g @qed-proof/cli
```

## Commands

```bash
qed login                 # prompts for the API key without echoing it (or: qed login --key-stdin)
qed logout

qed claim <action> --target T [--param k=v ...] [--agent ID] [--id CLIENT_ID] [--wait] [--json]
qed claims list [--limit N] [--agent ID] [--action A] [--verdict V] [--state S] [--all] [--json]
qed receipts get <id> [--json]
qed watch <claim-id> [--json]

qed verify <file|https-url> [--keys file|url] [--rpc url] [--pipeline file] [--json]   # offline check, exit 1 if not valid
qed verify <file> --head <file|url> [--consistency <file> ...] [--issuer <url>]        # also check the log (below)
# At trust level 3 `qed verify` also prints `attestation:` (the AWS Nitro Enclaves check). `--nitro-root <file>` swaps the
# trusted root for a test one; never use it on real receipts.

qed log head [--verify] [--keys file|url] [--json]   # the public signed tree head; no API key needed
```

### Checking against the public log

The log is public and read-only (no API key). `--head` takes a signed tree head (SPEC section 8.5), either a file or
the issuer's `/v1/log/head` URL; the receipt must verify against the head's signature and its tree must be a prefix of
the head's tree. A proof between two tree sizes (SPEC section 8.4) is taken from a `--consistency` file (a saved
`/v1/log/consistency` response, repeatable) or fetched from `--issuer` (a head URL ending in `/v1/log/head` names the
issuer itself). With `--head`, `qed verify` prints a `head:` line and exits 1 if it fails.

`qed log head` prints the size, root, signing key id and latest anchor of the issuer (`QED_PROOF_BASE_URL`, the saved
base URL, or `https://api.qedproof.site`). `--verify` checks the head's signature against the issuer's
`/.well-known/poaw-keys.json` (or `--keys`) and exits 1 if it does not verify.

`QED_PROOF_API_KEY` and `QED_PROOF_BASE_URL` env vars override the saved config.

## Config

The API key is stored at mode `0600` in the OS config directory (never printed — only the last
4 characters, masked):

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/qed-proof/config.json` |
| Linux | `$XDG_CONFIG_HOME/qed-proof/config.json` or `~/.config/qed-proof/config.json` |
| Windows | `%APPDATA%\qed-proof\config.json` |

## License

Apache-2.0. See [LICENSE](LICENSE).
