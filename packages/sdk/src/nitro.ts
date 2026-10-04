/**
 * AWS Nitro Enclaves attestation verification (SPEC.md §7.1, trust level 3), ported from
 * `oss/core-python/src/poaw_core/nitro.py`.
 *
 * `verifyNitroAttestation` checks the COSE_Sign1 document and its certificate chain to the pinned AWS Nitro root.
 * `verifyEnclaveReceipt` adds the receipt-level rules (PCR0 = code_hash, user_data = statement digest, published build).
 * Every failure throws `AttestationError` with one of the reason codes in `ATTESTATION_REASONS`.
 *
 * No dependency beyond the ones the SDK already has, and nothing is evaluated at runtime (strict-CSP safe):
 *  - CBOR: a small strict decoder for the subset an attestation document uses (ints, byte/text strings, arrays, maps,
 *    null/booleans, definite and indefinite lengths, and tag 18 on the outer COSE_Sign1). It rejects floats, other
 *    tags, duplicate map keys, trailing bytes and excessive nesting.
 *  - X.509: a minimal DER reader for exactly the fields a Nitro chain needs (tbsCertificate, signatureAlgorithm,
 *    signatureValue, issuer/subject names, validity, subjectPublicKeyInfo, basicConstraints). Only ecdsa-with-SHA384 over
 *    P-384 is accepted, which is what the AWS Nitro PKI uses; anything else is an `attestation_chain` failure.
 *  - ECDSA P-384 via @noble/curves (synchronous, no WebCrypto, so it also runs on Node 18).
 */
import { p384 } from "@noble/curves/p384";
import { sha384 } from "@noble/hashes/sha2";
import { b64u, b64uDecode, bytesEqual, jcs, sha256 } from "./primitives.js";

export const ATTESTATION_TYPE = "aws-nitro-enclave";
export const NITRO_ROOT_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";
/** AWS Nitro Enclaves root, G1 (https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip). */
export const NITRO_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
`;

export const ATTESTATION_REASONS = [
  "attestation_invalid",
  "attestation_chain",
  "pcr_mismatch",
  "statement_mismatch",
  "unknown_build",
] as const;
export type AttestationReason = (typeof ATTESTATION_REASONS)[number];

/** An attestation that does not verify. `reason` is one of ATTESTATION_REASONS (SPEC §7.1). */
export class AttestationError extends Error {
  readonly reason: AttestationReason;
  readonly detail: string;
  constructor(reason: AttestationReason, detail = "") {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "AttestationError";
    this.reason = reason;
    this.detail = detail;
  }
}

export interface NitroAttestation {
  moduleId: string;
  digest: string;
  /** Milliseconds since the Unix epoch, as the NSM reports it. */
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  userData: Uint8Array | null;
  nonce: Uint8Array | null;
  publicKey: Uint8Array | null;
}

export interface VerifierBuild {
  code_hash?: string;
  [key: string]: unknown;
}

function hex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

function bad(detail: string): AttestationError {
  return new AttestationError("attestation_invalid", detail);
}

// --- trust anchor ------------------------------------------------------------------------------------------------

/** A PEM (string) or DER (bytes) X.509 certificate to DER bytes. */
export function certToDer(cert: string | Uint8Array): Uint8Array {
  if (typeof cert !== "string") return cert;
  const m = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(cert);
  if (!m) throw new TypeError("not a PEM certificate");
  const body = m[1].replace(/\s+/g, "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return b64uDecode(body);
}

export const NITRO_ROOT_DER: Uint8Array = certToDer(NITRO_ROOT_PEM);
if (hex(sha256(NITRO_ROOT_DER)) !== NITRO_ROOT_SHA256) {
  // fail loudly: never run with a wrong trust anchor
  throw new Error("embedded AWS Nitro root does not match its pinned SHA-256 fingerprint");
}

// --- strict CBOR subset decoder ----------------------------------------------------------------------------------

const MAX_DEPTH = 16;
const BREAK = 0xff;

class CborError extends Error {}

/** A decoded CBOR map. Keys are ints, text strings or byte strings; each kind is looked up with its own getter. */
export class CborMap {
  readonly entries = new Map<string, unknown>();
  get size(): number {
    return this.entries.size;
  }
  private static id(key: number | bigint | string | Uint8Array): string {
    if (typeof key === "string") return "s:" + key;
    if (typeof key === "number" || typeof key === "bigint") return "i:" + String(key);
    return "b:" + hex(key);
  }
  /** Returns false if the key was already present. */
  add(key: number | bigint | string | Uint8Array, value: unknown): boolean {
    const id = CborMap.id(key);
    if (this.entries.has(id)) return false;
    this.entries.set(id, value);
    return true;
  }
  get(key: number | bigint | string | Uint8Array): unknown {
    return this.entries.get(CborMap.id(key));
  }
  /** [int key, value] pairs, for maps whose keys must all be ints. Null if any key is not an int. */
  intEntries(): Array<[number, unknown]> | null {
    const out: Array<[number, unknown]> = [];
    for (const [id, v] of this.entries) {
      if (!id.startsWith("i:")) return null;
      const n = Number(id.slice(2));
      if (!Number.isSafeInteger(n)) return null;
      out.push([n, v]);
    }
    return out;
  }
}

type Head = { major: number; arg: number | bigint; pos: number };
const INDEFINITE = -1;

function readHead(data: Uint8Array, pos: number): Head {
  if (pos >= data.length) throw new CborError("truncated");
  const major = data[pos] >> 5;
  const ai = data[pos] & 0x1f;
  pos++;
  if (ai < 24) return { major, arg: ai, pos };
  if (ai === 31 && major >= 2 && major <= 5) {
    // Indefinite length (RFC 8949 §3.2): the real NSM encodes its attestation payload map this way. The COSE signature
    // still covers the exact bytes, so accepting it costs nothing; the caller reads until the break (0xff).
    return { major, arg: INDEFINITE, pos };
  }
  if (ai > 27) throw new CborError("reserved additional info");
  const n = 1 << (ai - 24);
  if (pos + n > data.length) throw new CborError("truncated");
  let v = 0n;
  for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(data[pos + i]);
  return { major, arg: v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v, pos: pos + n };
}

function toLen(arg: number | bigint, data: Uint8Array, pos: number): number {
  if (typeof arg !== "number" || pos + arg > data.length) throw new CborError("truncated");
  return arg;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });
function text(raw: Uint8Array): string {
  try {
    return utf8.decode(raw);
  } catch {
    throw new CborError("invalid utf-8");
  }
}

function addKey(m: CborMap, k: unknown, v: unknown): void {
  if (typeof k !== "number" && typeof k !== "bigint" && typeof k !== "string" && !(k instanceof Uint8Array)) {
    throw new CborError("unsupported map key");
  }
  if (!m.add(k, v)) throw new CborError("duplicate map key");
}

function decode(data: Uint8Array, pos: number, depth: number): [unknown, number] {
  if (depth > MAX_DEPTH) throw new CborError("nested too deeply");
  if (pos < data.length && data[pos] >> 5 === 7) {
    // simple values: only false/true/null
    const simple = data[pos] & 0x1f;
    if (simple === 20) return [false, pos + 1];
    if (simple === 21) return [true, pos + 1];
    if (simple === 22) return [null, pos + 1];
    throw new CborError("unsupported simple value or float");
  }
  const h = readHead(data, pos);
  if (h.arg === INDEFINITE) return decodeIndefinite(data, h.pos, h.major, depth);
  const { major, arg } = h;
  pos = h.pos;
  if (major === 0) return [arg, pos];
  if (major === 1) return [typeof arg === "number" ? -1 - arg : -1n - arg, pos];
  if (major === 2 || major === 3) {
    const n = toLen(arg, data, pos);
    const raw = data.slice(pos, pos + n);
    return [major === 2 ? raw : text(raw), pos + n];
  }
  if (major === 4) {
    if (typeof arg !== "number" || arg > data.length - pos) throw new CborError("truncated"); // every item takes >= 1 byte
    const out: unknown[] = [];
    for (let i = 0; i < arg; i++) {
      const [item, p] = decode(data, pos, depth + 1);
      out.push(item);
      pos = p;
    }
    return [out, pos];
  }
  if (major === 5) {
    if (typeof arg !== "number" || arg > data.length - pos) throw new CborError("truncated");
    const m = new CborMap();
    for (let i = 0; i < arg; i++) {
      const [k, p1] = decode(data, pos, depth + 1);
      const [v, p2] = decode(data, p1, depth + 1);
      addKey(m, k, v);
      pos = p2;
    }
    return [m, pos];
  }
  throw new CborError("tags are only allowed on the outer COSE_Sign1"); // major 6
}

/** Indefinite-length string, array or map, terminated by the break byte. Strings are definite-length chunks of the
 * same major type (RFC 8949 §3.2.3). */
function decodeIndefinite(data: Uint8Array, pos: number, major: number, depth: number): [unknown, number] {
  const atBreak = (p: number): boolean => {
    if (p >= data.length) throw new CborError("truncated (no break)");
    return data[p] === BREAK;
  };
  if (major === 2 || major === 3) {
    const parts: Uint8Array[] = [];
    while (!atBreak(pos)) {
      const h = readHead(data, pos);
      if (h.major !== major || h.arg === INDEFINITE) throw new CborError("bad indefinite string chunk");
      const n = toLen(h.arg, data, h.pos);
      parts.push(data.slice(h.pos, h.pos + n));
      pos = h.pos + n;
    }
    const total = parts.reduce((a, p) => a + p.length, 0);
    const raw = new Uint8Array(total);
    let o = 0;
    for (const p of parts) {
      raw.set(p, o);
      o += p.length;
    }
    return [major === 2 ? raw : text(raw), pos + 1];
  }
  if (major === 4) {
    const out: unknown[] = [];
    while (!atBreak(pos)) {
      const [item, p] = decode(data, pos, depth + 1);
      out.push(item);
      pos = p;
    }
    return [out, pos + 1];
  }
  const m = new CborMap();
  while (!atBreak(pos)) {
    const [k, p1] = decode(data, pos, depth + 1);
    const [v, p2] = decode(data, p1, depth + 1);
    addKey(m, k, v);
    pos = p2;
  }
  return [m, pos + 1];
}

/** Decode exactly one CBOR item (the subset above). Throws otherwise. */
export function cborDecode(data: Uint8Array): unknown {
  const [value, pos] = decode(data, 0, 0);
  if (pos !== data.length) throw new CborError("trailing bytes");
  return value;
}

// --- COSE_Sign1 --------------------------------------------------------------------------------------------------

const COSE_ES384 = -35;
const TAG_COSE_SIGN1 = 0xd2; // CBOR tag 18, one-byte head

interface Cose {
  protectedBytes: Uint8Array;
  payload: CborMap;
  payloadBytes: Uint8Array;
  signature: Uint8Array;
}

const isBytes = (v: unknown): v is Uint8Array => v instanceof Uint8Array;

function parseCose(document: Uint8Array): Cose {
  let cose: unknown;
  let protectedBytes: Uint8Array;
  let payloadBytes: Uint8Array;
  let signature: Uint8Array;
  let payload: unknown;
  try {
    cose = cborDecode(document[0] === TAG_COSE_SIGN1 ? document.subarray(1) : document);
    if (!(Array.isArray(cose) && cose.length === 4 && isBytes(cose[0]) && cose[1] instanceof CborMap && isBytes(cose[2]) && isBytes(cose[3]))) {
      throw bad("not a COSE_Sign1 array of four");
    }
    [protectedBytes, , payloadBytes, signature] = cose as [Uint8Array, unknown, Uint8Array, Uint8Array];
    const header = cborDecode(protectedBytes);
    if (!(header instanceof CborMap && header.size === 1 && header.get(1) === COSE_ES384)) {
      throw bad("protected header is not {alg: ES384}");
    }
    payload = cborDecode(payloadBytes);
  } catch (e) {
    if (e instanceof CborError) throw bad(`cbor: ${e.message}`);
    throw e;
  }
  if (!(payload instanceof CborMap)) throw bad("payload is not a map");
  return { protectedBytes, payload, payloadBytes, signature };
}

function fields(p: CborMap): NitroAttestation {
  const need = (key: string, kind: "string" | "int" | "bytes" | "map", optional = false): unknown => {
    const v = p.get(key);
    if ((v === undefined || v === null) && optional) return null;
    const ok =
      kind === "string" ? typeof v === "string"
      : kind === "int" ? typeof v === "number"
      : kind === "bytes" ? isBytes(v)
      : v instanceof CborMap;
    if (!ok) throw bad(`payload field '${key}' missing or of the wrong type`);
    return v;
  };
  const pcrMap = need("pcrs", "map") as CborMap;
  const pcrEntries = pcrMap.intEntries();
  if (pcrMap.size === 0 || pcrEntries === null || pcrEntries.some(([, v]) => !isBytes(v))) {
    throw bad("pcrs must be a non-empty map of int to bytes");
  }
  const digest = need("digest", "string") as string;
  if (digest !== "SHA384") throw bad("digest is not SHA384");
  return {
    moduleId: need("module_id", "string") as string,
    digest,
    timestamp: need("timestamp", "int") as number,
    pcrs: new Map(pcrEntries as Array<[number, Uint8Array]>),
    userData: need("user_data", "bytes", true) as Uint8Array | null,
    nonce: need("nonce", "bytes", true) as Uint8Array | null,
    publicKey: need("public_key", "bytes", true) as Uint8Array | null,
  };
}

// --- minimal DER / X.509 -----------------------------------------------------------------------------------------

class DerError extends Error {}

interface Tlv {
  tag: number;
  /** Offset of the whole TLV, of its content, and just past its end. */
  start: number;
  vStart: number;
  end: number;
}

function readTlv(d: Uint8Array, pos: number, limit = d.length): Tlv {
  if (pos + 2 > limit) throw new DerError("truncated");
  const tag = d[pos];
  if ((tag & 0x1f) === 0x1f) throw new DerError("high tag numbers are not used");
  let len = d[pos + 1];
  let vStart = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || vStart + n > limit) throw new DerError("bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + d[vStart + i];
    if (len < 128 || (n > 1 && d[vStart] === 0)) throw new DerError("non-minimal length");
    vStart += n;
  }
  if (vStart + len > limit) throw new DerError("truncated");
  return { tag, start: pos, vStart, end: vStart + len };
}

/** The child TLVs of a constructed element. */
function children(d: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = t.vStart;
  while (p < t.end) {
    const c = readTlv(d, p, t.end);
    out.push(c);
    p = c.end;
  }
  return out;
}

const expect = (t: Tlv | undefined, tag: number, what: string): Tlv => {
  if (!t || t.tag !== tag) throw new DerError(`${what}: unexpected structure`);
  return t;
};

const slice = (d: Uint8Array, t: Tlv): Uint8Array => d.subarray(t.start, t.end);

// ecdsa-with-SHA384 AlgorithmIdentifier (RFC 5758): SEQUENCE { OID 1.2.840.10045.4.3.3 }, parameters absent.
const SIG_ALG_ES384 = new Uint8Array([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);
// id-ecPublicKey + secp384r1, as the AlgorithmIdentifier inside a SubjectPublicKeyInfo.
const SPKI_ALG_P384 = new Uint8Array([
  0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
]);
const OID_BASIC_CONSTRAINTS = new Uint8Array([0x06, 0x03, 0x55, 0x1d, 0x13]);

interface Cert {
  tbs: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: number;
  notAfter: number;
  /** Uncompressed P-384 point (0x04 || X || Y), or null when the key is not a P-384 key. */
  p384Key: Uint8Array | null;
  sigAlgOk: boolean;
  /** DER ECDSA-Sig-Value. */
  signature: Uint8Array;
  basicConstraints: { ca: boolean; pathLen: number | null } | null;
}

function parseTime(d: Uint8Array, t: Tlv): number {
  const s = new TextDecoder().decode(d.subarray(t.vStart, t.end));
  const m = t.tag === 0x17 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s) : t.tag === 0x18 ? /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s) : null;
  if (!m) throw new DerError("bad time");
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year >= 50 ? 1900 : 2000; // RFC 5280 §4.1.2.5.1
  const ms = Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  if (Number.isNaN(ms)) throw new DerError("bad time");
  return ms;
}

function parseBasicConstraints(d: Uint8Array, ext: Tlv): { ca: boolean; pathLen: number | null } | null {
  const exts = children(d, ext); // SEQUENCE OF Extension
  for (const e of exts) {
    const parts = children(d, expect(e, 0x30, "extension"));
    const oid = parts[0];
    if (!oid || !bytesEqual(slice(d, oid), OID_BASIC_CONSTRAINTS)) continue;
    const value = parts[parts.length - 1];
    expect(value, 0x04, "extension value");
    const inner = expect(readTlv(d, value.vStart, value.end), 0x30, "basicConstraints");
    if (inner.end !== value.end) throw new DerError("trailing bytes in basicConstraints");
    let ca = false;
    let pathLen: number | null = null;
    for (const c of children(d, inner)) {
      if (c.tag === 0x01) ca = d[c.vStart] !== 0;
      else if (c.tag === 0x02) {
        if (c.end - c.vStart !== 1 || d[c.vStart] & 0x80) throw new DerError("unsupported pathLenConstraint");
        pathLen = d[c.vStart];
      }
    }
    return { ca, pathLen };
  }
  return null;
}

function parseCert(d: Uint8Array): Cert {
  const top = expect(readTlv(d, 0), 0x30, "certificate");
  if (top.end !== d.length) throw new DerError("trailing bytes after certificate");
  const [tbsT, algT, sigT, ...rest] = children(d, top);
  if (rest.length) throw new DerError("certificate has extra elements");
  expect(tbsT, 0x30, "tbsCertificate");
  expect(algT, 0x30, "signatureAlgorithm");
  expect(sigT, 0x03, "signatureValue");
  if (d[sigT.vStart] !== 0) throw new DerError("signature has unused bits");
  const tbsKids = children(d, tbsT);
  let i = 0;
  if (tbsKids[i]?.tag === 0xa0) i++; // [0] version
  expect(tbsKids[i++], 0x02, "serialNumber");
  const innerAlg = expect(tbsKids[i++], 0x30, "tbs signature");
  const issuer = expect(tbsKids[i++], 0x30, "issuer");
  const validity = expect(tbsKids[i++], 0x30, "validity");
  const subject = expect(tbsKids[i++], 0x30, "subject");
  const spki = expect(tbsKids[i++], 0x30, "subjectPublicKeyInfo");
  const [nb, na] = children(d, validity);
  let basicConstraints: Cert["basicConstraints"] = null;
  for (; i < tbsKids.length; i++) {
    if (tbsKids[i].tag === 0xa3) {
      const seq = expect(readTlv(d, tbsKids[i].vStart, tbsKids[i].end), 0x30, "extensions");
      basicConstraints = parseBasicConstraints(d, seq);
    }
  }
  const [spkiAlg, spkiBits] = children(d, spki);
  let p384Key: Uint8Array | null = null;
  if (spkiBits && spkiBits.tag === 0x03 && bytesEqual(slice(d, spkiAlg), SPKI_ALG_P384) && d[spkiBits.vStart] === 0) {
    p384Key = d.slice(spkiBits.vStart + 1, spkiBits.end);
  }
  const algBytes = slice(d, algT);
  return {
    tbs: slice(d, tbsT),
    issuer: slice(d, issuer),
    subject: slice(d, subject),
    notBefore: parseTime(d, expect(nb, nb?.tag === 0x18 ? 0x18 : 0x17, "notBefore")),
    notAfter: parseTime(d, expect(na, na?.tag === 0x18 ? 0x18 : 0x17, "notAfter")),
    p384Key,
    sigAlgOk: bytesEqual(algBytes, SIG_ALG_ES384) && bytesEqual(slice(d, innerAlg), algBytes),
    signature: d.slice(sigT.vStart + 1, sigT.end),
    basicConstraints,
  };
}

function chainFail(detail: string): AttestationError {
  return new AttestationError("attestation_chain", detail);
}

/** True if `cert` carries a valid ecdsa-with-SHA384 signature by `issuer`, and names it as its issuer. */
function directlyIssuedBy(cert: Cert, issuer: Cert): boolean {
  if (!cert.sigAlgOk || issuer.p384Key === null || !bytesEqual(cert.issuer, issuer.subject)) return false;
  try {
    return p384.verify(cert.signature, sha384(cert.tbs), issuer.p384Key, { format: "der", lowS: false });
  } catch {
    return false;
  }
}

/** §7.1 step 2: cabundle[0] is the pinned root; root → … → leaf verify, intermediates are CAs, all valid at `when`. */
function verifyChain(rootDer: Uint8Array, bundle: unknown, leafDer: unknown, when: number): Cert {
  if (!Array.isArray(bundle) || bundle.length === 0 || !bundle.every(isBytes) || !isBytes(leafDer)) {
    throw bad("cabundle/certificate missing or malformed");
  }
  if (!bytesEqual(bundle[0], rootDer)) throw chainFail("cabundle[0] is not the trusted root");
  let chain: Cert[];
  try {
    chain = [...bundle, leafDer].map(parseCert);
  } catch (e) {
    if (e instanceof DerError) throw chainFail(`chain does not verify (${e.message})`);
    throw e;
  }
  chain.forEach((c, i) => {
    if (!(c.notBefore <= when && when <= c.notAfter)) throw chainFail(`certificate ${i} is not valid at the attestation time`);
  });
  for (let i = 0; i < chain.length - 1; i++) {
    const bc = chain[i].basicConstraints;
    if (bc === null) throw chainFail("chain does not verify (ExtensionNotFound)");
    if (!bc.ca) throw chainFail(`certificate ${i} is not a CA`);
    if (bc.pathLen !== null && chain.length - 2 - i > bc.pathLen) throw chainFail(`certificate ${i} path length exceeded`);
    if (!directlyIssuedBy(chain[i + 1], chain[i])) throw chainFail("chain does not verify (InvalidSignature)");
  }
  return chain[chain.length - 1];
}

function cborBstrHead(n: number): number[] {
  if (n < 24) return [0x40 | n];
  if (n < 256) return [0x58, n];
  if (n < 65536) return [0x59, n >> 8, n & 0xff];
  return [0x5a, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

/** The COSE Sig_structure: ["Signature1", protected, h'', payload]. */
function sigStructure(protectedBytes: Uint8Array, payloadBytes: Uint8Array): Uint8Array {
  const head = [0x84, 0x6a, ...new TextEncoder().encode("Signature1"), ...cborBstrHead(protectedBytes.length)];
  const mid = [0x40, ...cborBstrHead(payloadBytes.length)]; // external_aad is the empty byte string
  const out = new Uint8Array(head.length + protectedBytes.length + mid.length + payloadBytes.length);
  out.set(head, 0);
  out.set(protectedBytes, head.length);
  out.set(mid, head.length + protectedBytes.length);
  out.set(payloadBytes, head.length + protectedBytes.length + mid.length);
  return out;
}

export interface NitroVerifyOptions {
  /** TESTS ONLY: trust this certificate (PEM text or DER bytes) instead of the pinned AWS Nitro root. */
  nitroRoot?: string | Uint8Array;
  /** Replaces the document's own timestamp as the time certificates must be valid at (epoch milliseconds). */
  at?: number;
}

const B64U = /^[A-Za-z0-9_-]*={0,2}$/;

function decodeDocument(documentB64u: string): Uint8Array {
  try {
    if (typeof documentB64u !== "string" || !B64U.test(documentB64u)) throw new Error("alphabet");
    return b64uDecode(documentB64u);
  } catch {
    throw bad("document is not base64url");
  }
}

/** SPEC §7.1 steps 1–3. Throws AttestationError(attestation_invalid | attestation_chain). */
export function verifyNitroAttestation(documentB64u: string, options: NitroVerifyOptions = {}): NitroAttestation {
  const document = decodeDocument(documentB64u);
  const { protectedBytes, payload, payloadBytes, signature } = parseCose(document);
  const att = fields(payload);
  const when = options.at ?? att.timestamp;
  const rootDer = options.nitroRoot !== undefined ? certToDer(options.nitroRoot) : NITRO_ROOT_DER;
  const leaf = verifyChain(rootDer, payload.get("cabundle"), payload.get("certificate"), when);
  if (leaf.p384Key === null || signature.length !== 96) throw bad("leaf key is not P-384 or signature is not 96 bytes");
  let ok = false;
  try {
    ok = p384.verify(signature, sha384(sigStructure(protectedBytes, payloadBytes)), leaf.p384Key, { format: "compact", lowS: false });
  } catch {
    ok = false;
  }
  if (!ok) throw bad("COSE signature does not verify");
  return att;
}

/** SPEC §4: base64url(SHA-256(raw COSE_Sign1 bytes)), the value a level-3 body carries as `attestation.document_sha256`. */
export function attestationDocumentSha256(documentB64u: string): string {
  return b64u(sha256(b64uDecode(documentB64u)));
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/** A required member (Python's `d[key]`): throws if `d` is not an object or lacks `key`. */
function req(d: unknown, key: string): unknown {
  if (!isObj(d) || !Object.prototype.hasOwnProperty.call(d, key)) throw new TypeError(`missing ${key}`);
  return d[key];
}

/** SPEC §7.1: what an enclave attests to for a receipt body: the claim digest, the verifier id and version, when it
 * looked, the facts, and the verdict. */
export function enclaveStatement(body: unknown): Obj {
  const obs = req(body, "observation");
  const verifier = req(obs, "verifier");
  return {
    claim_digest: req(req(body, "claim"), "claim_digest"),
    verifier: { id: req(verifier, "id"), version: req(verifier, "version") },
    observed_at: req(obs, "observed_at"),
    facts: req(obs, "facts"),
    verdict: req(body, "verdict"),
  };
}

/** SPEC §7.1: SHA-256(JCS(statement)), the 32 bytes the enclave puts in the attestation document's `user_data`. */
export function enclaveStatementDigest(body: unknown): Uint8Array {
  return sha256(jcs(enclaveStatement(body)));
}

const CODE_HASH = /^sha384:[0-9a-f]{96}$/;

/**
 * SPEC §7.1 steps 1–5 for a whole receipt at trust level >= 3. The body commits to the document by hash
 * (`attestation.document_sha256`); the document itself is the receipt's top-level `attestation_document`.
 * `verifierBuilds` is the issuer's poaw-keys.json `verifier_builds`. Throws AttestationError with one of
 * ATTESTATION_REASONS; returns the parsed attestation when everything holds.
 */
export function verifyEnclaveReceipt(
  receipt: unknown,
  verifierBuilds: VerifierBuild[] | undefined | null,
  options: NitroVerifyOptions = {},
): NitroAttestation {
  const body = isObj(receipt) ? receipt.body : undefined;
  const attestation = isObj(body) ? body.attestation : undefined;
  if (!isObj(attestation) || attestation.type !== ATTESTATION_TYPE || typeof attestation.document_sha256 !== "string") {
    throw bad("attestation is not an aws-nitro-enclave document hash");
  }
  const document = (receipt as Obj).attestation_document;
  if (typeof document !== "string" || document === "") throw bad("the receipt carries no attestation_document");
  let digestOk: boolean;
  try {
    decodeDocument(document);
    digestOk = attestationDocumentSha256(document) === attestation.document_sha256;
  } catch {
    throw bad("attestation_document is not base64url");
  }
  if (!digestOk) throw bad("attestation_document does not match attestation.document_sha256");
  const att = verifyNitroAttestation(document, options);
  let codeHash: unknown;
  let digest: Uint8Array;
  try {
    codeHash = req(req(req(body, "observation"), "verifier"), "code_hash");
    digest = enclaveStatementDigest(body);
  } catch {
    throw bad("receipt body lacks the fields the statement covers");
  }
  const pcr0 = att.pcrs.get(0);
  if (typeof codeHash !== "string" || !CODE_HASH.test(codeHash) || pcr0 === undefined || codeHash !== "sha384:" + hex(pcr0)) {
    throw new AttestationError("pcr_mismatch", "PCR0 is not the receipt's code_hash");
  }
  if (att.userData === null || !bytesEqual(att.userData, digest)) {
    throw new AttestationError("statement_mismatch", "user_data is not the statement digest");
  }
  if (!(verifierBuilds ?? []).some((b) => isObj(b) && b.code_hash === codeHash)) {
    throw new AttestationError("unknown_build", "code_hash is not a published verifier build");
  }
  return att;
}
