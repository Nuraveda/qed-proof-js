import { describe, expect, it, vi } from "vitest";
import { QedProof } from "../src/client.js";
import { QedProofError, RateLimitError } from "../src/errors.js";
import { githubCommitPush } from "../src/actions.js";

function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers },
  });
}

describe("QedProof client", () => {
  it("submits a claim with the built action and options", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return jsonResponse({ claim_id: "c1", created: true, state: "queued", attempts: 1, receipt_id: null, verdict: null });
    });
    const qp = new QedProof({ apiKey: "qed_sk_test", baseUrl: "https://api.example.test", fetch: fetchMock as unknown as typeof fetch });

    const action = githubCommitPush({ target: "acme/widgets", sha: "a".repeat(40), branch: "main" });
    const result = await qp.submitClaim(action, { agentId: "agent-1", clientClaimId: "deploy-42" });

    expect(result.claim_id).toBe("c1");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://api.example.test/v1/claims");
    expect((calls[0].init.headers as Record<string, string>).authorization).toBe("Bearer qed_sk_test");
    const body = JSON.parse(calls[0].init.body as string);
    expect(body).toMatchObject({
      client_claim_id: "deploy-42",
      agent_id: "agent-1",
      action: "github.commit.push",
      target: "acme/widgets",
      params: { sha: "a".repeat(40), branch: "main" },
    });
    expect(typeof body.claimed_at).toBe("string");
  });

  it("resubmitting the same client_claim_id is idempotent (created: false)", async () => {
    let n = 0;
    const fetchMock = vi.fn(async () => {
      n += 1;
      return jsonResponse({ claim_id: "c1", created: n === 1, state: "queued", attempts: n, receipt_id: null, verdict: null });
    });
    const qp = new QedProof({ apiKey: "k", fetch: fetchMock as unknown as typeof fetch });
    const action = githubCommitPush({ target: "acme/widgets", sha: "a".repeat(40), branch: "main" });

    const first = await qp.submitClaim(action, { agentId: "a", clientClaimId: "same-id" });
    const second = await qp.submitClaim(action, { agentId: "a", clientClaimId: "same-id" });

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(first.claim_id).toBe(second.claim_id);
  });

  it("waitForVerdict polls until decided", async () => {
    let n = 0;
    const fetchMock = vi.fn(async () => {
      n += 1;
      const state = n < 3 ? "queued" : "decided";
      return jsonResponse({ claim_id: "c1", state, attempts: n, receipt_id: state === "decided" ? "r1" : null, verdict: state === "decided" ? "verified" : null });
    });
    const qp = new QedProof({ apiKey: "k", fetch: fetchMock as unknown as typeof fetch });

    const result = await qp.waitForVerdict("c1", { pollIntervalMs: 1, timeoutMs: 5000 });
    expect(result.state).toBe("decided");
    expect(result.receipt_id).toBe("r1");
    expect(n).toBe(3);
  });

  it("waitForVerdict times out", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ claim_id: "c1", state: "queued", attempts: 1, receipt_id: null, verdict: null }));
    const qp = new QedProof({ apiKey: "k", fetch: fetchMock as unknown as typeof fetch });

    await expect(qp.waitForVerdict("c1", { pollIntervalMs: 1, timeoutMs: 5 })).rejects.toThrow(QedProofError);
  });

  it("a 401 raises QedProofError with status 401", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ detail: "invalid or missing API key" }, { status: 401 }));
    const qp = new QedProof({ apiKey: "bad-key", fetch: fetchMock as unknown as typeof fetch });

    await expect(qp.getClaim("c1")).rejects.toMatchObject({ status: 401, detail: "invalid or missing API key" });
  });

  it("a 429 raises RateLimitError with Retry-After honoured", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ detail: "rate limit exceeded" }, { status: 429, headers: { "Retry-After": "5" } }),
    );
    const qp = new QedProof({ apiKey: "k", fetch: fetchMock as unknown as typeof fetch });

    let caught: unknown;
    try {
      await qp.getClaim("c1");
    } catch (exc) {
      caught = exc;
    }
    expect(caught).toBeInstanceOf(RateLimitError);
    expect((caught as RateLimitError).retryAfter).toBe(5);
  });

  it("getReceipt sends no Authorization header", async () => {
    const calls: RequestInit[] = [];
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      calls.push(init);
      return jsonResponse({ body: {}, signature: {} });
    });
    const qp = new QedProof({ apiKey: "super-secret-key", fetch: fetchMock as unknown as typeof fetch });

    await qp.getReceipt("r1");
    expect(calls).toHaveLength(1);
    expect((calls[0].headers as Record<string, string>).authorization).toBeUndefined();
  });

  it("listClaims sends expected params and auth, omitting undefined filters", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return jsonResponse({ claims: [{ claim_id: "c1", state: "decided", attempts: 1, receipt_id: "r1", verdict: "verified" }], next_cursor: null });
    });
    const qp = new QedProof({ apiKey: "qed_sk_test", baseUrl: "https://api.example.test", fetch: fetchMock as unknown as typeof fetch });

    const page = await qp.listClaims({ agentId: "agent-1" });

    expect(calls).toHaveLength(1);
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/v1/claims");
    expect(Object.fromEntries(url.searchParams)).toEqual({ limit: "50", agent_id: "agent-1" });
    expect((calls[0].init.headers as Record<string, string>).authorization).toBe("Bearer qed_sk_test");
    expect(page.claims[0].claim_id).toBe("c1");
    expect(page.nextCursor).toBeNull();
  });

  it("listClaims sends all filters when given", async () => {
    const calls: Array<{ url: string }> = [];
    const fetchMock = vi.fn(async (url: string) => {
      calls.push({ url });
      return jsonResponse({ claims: [], next_cursor: null });
    });
    const qp = new QedProof({ apiKey: "k", fetch: fetchMock as unknown as typeof fetch });

    await qp.listClaims({ limit: 10, cursor: "abc", agentId: "agent-1", action: "github.commit.push", verdict: "verified", state: "decided" });

    const url = new URL(calls[0].url);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      limit: "10", cursor: "abc", agent_id: "agent-1", action: "github.commit.push", verdict: "verified", state: "decided",
    });
  });

  it("listClaims rejects an out-of-range limit locally, without a request", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("no HTTP request should be made when limit is invalid");
    });
    const qp = new QedProof({ apiKey: "k", fetch: fetchMock as unknown as typeof fetch });

    await expect(qp.listClaims({ limit: 0 })).rejects.toThrow(RangeError);
    await expect(qp.listClaims({ limit: 201 })).rejects.toThrow(RangeError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("iterClaims follows nextCursor across two pages and stops", async () => {
    const cursorsSeen: Array<string | null> = [];
    const fetchMock = vi.fn(async (url: string) => {
      const cursor = new URL(url).searchParams.get("cursor");
      cursorsSeen.push(cursor);
      if (cursor === null) {
        return jsonResponse({
          claims: [
            { claim_id: "c1", state: "decided", attempts: 1, receipt_id: "r1", verdict: "verified" },
            { claim_id: "c2", state: "decided", attempts: 1, receipt_id: "r2", verdict: "verified" },
          ],
          next_cursor: "page2",
        });
      }
      return jsonResponse({ claims: [{ claim_id: "c3", state: "decided", attempts: 1, receipt_id: "r3", verdict: "verified" }], next_cursor: null });
    });
    const qp = new QedProof({ apiKey: "k", fetch: fetchMock as unknown as typeof fetch });

    const claims = [];
    for await (const claim of qp.iterClaims({ pageSize: 2 })) claims.push(claim);

    expect(claims.map((c) => c.claim_id)).toEqual(["c1", "c2", "c3"]);
    expect(cursorsSeen).toEqual([null, "page2"]);
  });

  it("error messages never include the API key", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("boom");
    });
    const qp = new QedProof({ apiKey: "super-secret-key", fetch: fetchMock as unknown as typeof fetch });
    let message = "";
    try {
      await qp.getClaim("c1");
    } catch (exc) {
      message = exc instanceof Error ? exc.message : String(exc);
    }
    expect(message).not.toContain("super-secret-key");
  });
});

describe("getReceipt keeps the JSON text for verification", () => {
  it("a 1.0 in a fetched receipt fails integers_only, as in the Python SDK (JSON.parse would hide it)", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const dir = fileURLToPath(new URL("../../../test/vectors/", import.meta.url));
    const good = readFileSync(dir + "001-valid-verified.json", "utf8");
    const keys = JSON.parse(readFileSync(dir + "keys.json", "utf8"));
    // Inject an integer written as a float into the body's facts; the value parses to the same number.
    const tampered = good.replace('"attempts": 1', '"attempts": 1.0');
    expect(tampered).not.toEqual(good);
    const fetchImpl = async () => new Response(tampered, { status: 200, headers: { "content-type": "application/json" } });
    const qp = new QedProof({ fetch: fetchImpl as typeof fetch });
    const receipt = await qp.getReceipt("rcpt_x");
    const report = await qp.verify(receipt, { keys });
    expect(report.checks.integers_only).toBe(false);
    expect(report.valid).toBe(false);
  });
});

describe("QedProof public log methods", () => {
  function setup(body: unknown) {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return jsonResponse(body);
    });
    const qp = new QedProof({ apiKey: "qed_sk_secret", baseUrl: "https://api.example.test/", fetch: fetchMock as unknown as typeof fetch });
    return { calls, qp };
  }
  const noAuth = (c: { init: RequestInit }) => expect((c.init.headers as Record<string, string>).authorization).toBeUndefined();

  it("logHead GETs /v1/log/head without a key", async () => {
    const head = { tree_head: { body: { log_id: "l", tree_size: 3, root_hash: "r", issued_at: "t" }, signature: {} }, anchor: null };
    const { calls, qp } = setup(head);
    expect(await qp.logHead()).toEqual(head);
    expect(calls[0].url).toBe("https://api.example.test/v1/log/head");
    noAuth(calls[0]);
  });

  it("logConsistency, logProof build the right queries without a key", async () => {
    const { calls, qp } = setup({ proof: [] });
    await qp.logConsistency(2, 5);
    await qp.logProof(4);
    await qp.logProof(4, 9);
    expect(calls.map((c) => c.url)).toEqual([
      "https://api.example.test/v1/log/consistency?first=2&second=5",
      "https://api.example.test/v1/log/proof?leaf_index=4",
      "https://api.example.test/v1/log/proof?leaf_index=4&tree_size=9",
    ]);
    calls.forEach(noAuth);
  });

  it("logAnchors and logEntries pass paging options, omitting unset ones", async () => {
    const { calls, qp } = setup({ anchors: [], entries: [], next: null });
    await qp.logAnchors();
    await qp.logAnchors({ limit: 10, before: 7 });
    await qp.logEntries();
    await qp.logEntries({ start: 0, limit: 100 });
    expect(calls.map((c) => c.url)).toEqual([
      "https://api.example.test/v1/log/anchors",
      "https://api.example.test/v1/log/anchors?limit=10&before=7",
      "https://api.example.test/v1/log/entries",
      "https://api.example.test/v1/log/entries?start=0&limit=100",
    ]);
    calls.forEach(noAuth);
  });

  it("rejects bad numbers locally and surfaces API errors", async () => {
    const { calls, qp } = setup({});
    await expect(qp.logConsistency(-1, 2)).rejects.toThrow(RangeError);
    await expect(qp.logProof(1.5)).rejects.toThrow(RangeError);
    expect(calls).toHaveLength(0);
    const f = vi.fn(async () => jsonResponse({ detail: "no such size" }, { status: 404 }));
    const qp2 = new QedProof({ fetch: f as unknown as typeof fetch });
    await expect(qp2.logConsistency(1, 99)).rejects.toMatchObject({ status: 404 });
  });
});
