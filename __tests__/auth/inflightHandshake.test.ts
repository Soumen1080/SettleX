/** @jest-environment jsdom */

/**
 * Regression tests for "the in-flight handshake promise is not keyed by wallet
 * address".
 *
 * The bug: `inFlight` was one module-level slot. A call for wallet B arriving
 * while wallet A was mid-handshake received A's promise, so the UI marked B
 * authenticated while every request was signed as A.
 */
import { CHALLENGE_ENDPOINT, VERIFY_ENDPOINT } from "@/lib/auth/constants";

const signXDR = jest.fn(async (xdr: string) => `signed:${xdr}`);
jest.mock("@/lib/freighter", () => ({ signXDR: (xdr: string) => signXDR(xdr) }));

const A = "GDQNY3PBOJOKYZSRMK2S7LHHGWZIUISD4QORETLMXEWXBI7KFZZMKTL3";
const B = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

/** Resolvable gate so a handshake can be held open mid-flight. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/**
 * Fake challenge/verify endpoints. Each wallet's verify response is gated so
 * the test controls exactly when a handshake completes.
 */
function mockEndpoints(gates: Record<string, Promise<void>>) {
  global.fetch = (async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    const wallet = body.walletAddress as string;

    if (String(url).includes(CHALLENGE_ENDPOINT)) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          transactionXdr: `xdr-for-${wallet}`,
          networkPassphrase: "Test SDF Network ; September 2015",
          challengeToken: `challenge-${wallet}`,
        }),
      } as unknown as Response;
    }

    if (String(url).includes(VERIFY_ENDPOINT)) {
      await gates[wallet];
      return {
        ok: true,
        status: 200,
        json: async () => ({
          accessToken: `token-for-${wallet}`,
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        }),
      } as unknown as Response;
    }

    throw new Error(`unexpected fetch: ${url}`);
  }) as unknown as typeof fetch;
}

describe("getWalletSession in-flight handling", () => {
  let session: typeof import("@/lib/supabase/session");

  beforeEach(() => {
    jest.resetModules();
    window.localStorage.clear();
    signXDR.mockClear();
    session = require("@/lib/supabase/session");
  });

  it("does not hand wallet B the session from wallet A's pending handshake", async () => {
    const gateA = deferred<void>();
    const gateB = deferred<void>();
    mockEndpoints({ [A]: gateA.promise, [B]: gateB.promise });

    // A starts signing; B arrives before A finishes.
    const pendingA = session.getWalletSession(A);
    const pendingB = session.getWalletSession(B);

    gateA.resolve();
    gateB.resolve();

    const [resultA, resultB] = await Promise.all([pendingA, pendingB]);

    expect(resultA?.walletAddress).toBe(A);
    expect(resultA?.accessToken).toBe(`token-for-${A}`);
    // The bug returned A's session (and A's token) here.
    expect(resultB?.walletAddress).toBe(B);
    expect(resultB?.accessToken).toBe(`token-for-${B}`);
  });

  it("still shares one handshake between concurrent calls for the same wallet", async () => {
    const gateA = deferred<void>();
    mockEndpoints({ [A]: gateA.promise });

    const first = session.getWalletSession(A);
    const second = session.getWalletSession(A);
    gateA.resolve();

    const [one, two] = await Promise.all([first, second]);

    expect(one).toEqual(two);
    // The whole point of the dedupe: one wallet prompt, not two.
    expect(signXDR).toHaveBeenCalledTimes(1);
  });

  it("prompts each wallet exactly once when two sign in concurrently", async () => {
    const gateA = deferred<void>();
    const gateB = deferred<void>();
    mockEndpoints({ [A]: gateA.promise, [B]: gateB.promise });

    const calls = [
      session.getWalletSession(A),
      session.getWalletSession(B),
      session.getWalletSession(A),
      session.getWalletSession(B),
    ];
    gateA.resolve();
    gateB.resolve();
    await Promise.all(calls);

    expect(signXDR).toHaveBeenCalledTimes(2);
  });

  it("lets a wallet sign in again after its handshake settles", async () => {
    const gateA = deferred<void>();
    mockEndpoints({ [A]: gateA.promise });

    gateA.resolve();
    const first = await session.getWalletSession(A);
    session.clearWalletSession();

    const gateA2 = deferred<void>();
    mockEndpoints({ [A]: gateA2.promise });
    gateA2.resolve();
    const second = await session.getWalletSession(A);

    expect(first?.walletAddress).toBe(A);
    expect(second?.walletAddress).toBe(A);
    expect(signXDR).toHaveBeenCalledTimes(2);
  });
});
