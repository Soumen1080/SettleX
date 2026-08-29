/**
 * Wallet-authenticated Supabase sessions.
 *
 * A Supabase client is only trusted with a wallet identity after the wallet has
 * signed a server-issued challenge (`/api/auth/challenge` → `/api/auth/verify`)
 * and the server has minted a JWT carrying a `wallet_address` claim. RLS
 * policies read that claim, so an access token cannot be forged client-side the
 * way the old `x-wallet-address` request header could.
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import {
  CHALLENGE_ENDPOINT,
  LS_SESSION,
  SESSION_REFRESH_SKEW_SECONDS,
  VERIFY_ENDPOINT,
} from "@/lib/auth/constants";
import { signXDR } from "@/lib/freighter";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;

export interface WalletSession {
  walletAddress: string;
  accessToken: string;
  /** Expiry in milliseconds since the epoch. */
  expiresAt: number;
}

/** Raised when the handshake could not complete (rejected signature, etc.). */
export class WalletSessionError extends Error {}

// ─── Cached session ───────────────────────────────────────────────────────────

function isFresh(session: WalletSession, now = Date.now()): boolean {
  return session.expiresAt - SESSION_REFRESH_SKEW_SECONDS * 1000 > now;
}

export function readStoredSession(walletAddress: string): WalletSession | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(LS_SESSION);
    if (!raw) return null;
    const session = JSON.parse(raw) as WalletSession;
    if (session.walletAddress !== walletAddress) return null;
    if (!session.accessToken || !isFresh(session)) return null;
    return session;
  } catch {
    return null;
  }
}

function storeSession(session: WalletSession): void {
  try {
    window.localStorage.setItem(LS_SESSION, JSON.stringify(session));
  } catch {
    // Private-mode browsers refuse writes — the in-memory copy still works.
  }
}

/** Drops the cached token so the next authenticated call re-runs the handshake. */
export function clearWalletSession(): void {
  memoizedSession = null;
  // Abandon any pending handshakes: whatever they resolve to belongs to a
  // session the user has just dropped. Each one still removes its own entry,
  // so this only stops a late arrival from being reused.
  inFlight.clear();
  if (memoizedClient) {
    void memoizedClient.client.removeAllChannels();
    memoizedClient = null;
  }
  if (typeof window !== "undefined") {
    try {
      window.localStorage.removeItem(LS_SESSION);
    } catch {
      // ignore
    }
  }
  notifySessionChange();
}

let memoizedSession: WalletSession | null = null;

/**
 * Pending handshakes, keyed by wallet address.
 *
 * A single shared slot meant that a call for wallet B arriving while wallet A
 * was still signing received A's promise, and therefore A's session — the UI
 * would mark B authenticated while every request was signed as A. Keying by
 * address keeps the dedupe (one wallet prompt per wallet) without ever handing
 * one wallet another's handshake.
 */
const inFlight = new Map<string, Promise<WalletSession>>();

// ─── Change notifications ─────────────────────────────────────────────────────

const listeners = new Set<() => void>();

function notifySessionChange(): void {
  listeners.forEach((listener) => listener());
}

/**
 * Notifies subscribers whenever the session is established or dropped, so
 * anything holding a client (a realtime subscription, say) can rebind to the
 * new token instead of quietly running on a stale one.
 *
 * Returns an unsubscribe function.
 */
export function onSessionChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// ─── Handshake ────────────────────────────────────────────────────────────────

async function postJson<T>(url: string, body: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new WalletSessionError(
      "Cannot reach the SettleX server to sign in. Please check your connection.",
    );
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    // fall through to the status-based message below
  }

  if (!response.ok) {
    const message = (payload as { error?: unknown } | null)?.error;
    throw new WalletSessionError(
      typeof message === "string" ? message : `Sign-in failed (HTTP ${response.status}).`,
    );
  }

  return payload as T;
}

async function runHandshake(walletAddress: string): Promise<WalletSession> {
  const challenge = await postJson<{
    transactionXdr: string;
    networkPassphrase: string;
    challengeToken: string;
  }>(CHALLENGE_ENDPOINT, { walletAddress });

  let signedTransactionXdr: string;
  try {
    signedTransactionXdr = await signXDR(challenge.transactionXdr, challenge.networkPassphrase);
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    throw new WalletSessionError(
      /reject|denied|cancel|declined/i.test(message)
        ? "Sign-in was cancelled in your wallet."
        : message || "Your wallet could not sign the sign-in request.",
    );
  }

  const verified = await postJson<{ accessToken: string; expiresAt: string }>(VERIFY_ENDPOINT, {
    walletAddress,
    signedTransactionXdr,
    challengeToken: challenge.challengeToken,
  });

  const session: WalletSession = {
    walletAddress,
    accessToken: verified.accessToken,
    expiresAt: new Date(verified.expiresAt).getTime(),
  };

  memoizedSession = session;
  storeSession(session);
  notifySessionChange();
  return session;
}

export interface SessionOptions {
  /**
   * Whether the wallet may be prompted for a signature. Pass `false` on
   * background reads so the app never pops a wallet dialog unprompted.
   */
  interactive?: boolean;
}

/**
 * Returns a valid session for `walletAddress`, running the signing handshake if
 * no cached token is usable. Concurrent callers share one handshake, so the
 * wallet is only ever asked to sign once.
 */
export async function getWalletSession(
  walletAddress: string,
  options: SessionOptions = {},
): Promise<WalletSession | null> {
  if (!walletAddress) throw new WalletSessionError("Wallet not connected.");

  const cached =
    memoizedSession &&
    memoizedSession.walletAddress === walletAddress &&
    isFresh(memoizedSession)
      ? memoizedSession
      : readStoredSession(walletAddress);

  if (cached) {
    memoizedSession = cached;
    return cached;
  }

  if (options.interactive === false) return null;

  let pending = inFlight.get(walletAddress);
  if (!pending) {
    pending = runHandshake(walletAddress).finally(() => {
      inFlight.delete(walletAddress);
    });
    inFlight.set(walletAddress, pending);
  }

  const session = await pending;

  // Belt and braces: never hand back a session for a different wallet, however
  // it was obtained. Callers act on this identity, so a mismatch must be an
  // error rather than a silently wrong session.
  if (session.walletAddress !== walletAddress) {
    throw new WalletSessionError("The session returned belongs to a different wallet.");
  }
  return session;
}

// ─── Authenticated client ─────────────────────────────────────────────────────

let memoizedClient: { token: string; client: SupabaseClient } | null = null;

function buildClient(accessToken: string): SupabaseClient {
  if (memoizedClient?.token === accessToken) return memoizedClient.client;

  if (memoizedClient) {
    void memoizedClient.client.removeAllChannels();
  }

  const client = createClient(supabaseUrl, supabaseAnonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    realtime: { params: { eventsPerSecond: 10 } },
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
  });

  // Realtime authorizes on its own socket, so it needs the token too — without
  // this, RLS-guarded change feeds deliver nothing.
  client.realtime.setAuth(accessToken);

  memoizedClient = { token: accessToken, client };
  return client;
}

/**
 * Supabase client bound to a proven wallet identity. Returns `null` only when
 * `interactive: false` was requested and no cached session exists.
 */
export async function getAuthenticatedClient(
  walletAddress: string,
  options: SessionOptions = {},
): Promise<SupabaseClient | null> {
  const session = await getWalletSession(walletAddress, options);
  if (!session) return null;
  return buildClient(session.accessToken);
}

/**
 * Same as `getAuthenticatedClient`, but always prompts when no cached session
 * exists. Use it for writes, where proceeding unauthenticated is never right.
 */
export async function requireAuthenticatedClient(
  walletAddress: string,
): Promise<SupabaseClient> {
  const client = await getAuthenticatedClient(walletAddress, { interactive: true });
  if (!client) throw new WalletSessionError("Wallet sign-in is required.");
  return client;
}
