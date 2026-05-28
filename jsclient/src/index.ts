import {
  base64UrlEncode,
  base64UrlDecode,
  ssePayload,
  offerPayload,
  answerPayload,
  icePayload,
} from "./crypto.js";

const DEFAULT_ICE_SERVERS: RTCIceServer[] = [
  { urls: "stun:stun.l.google.com:19302" },
];

const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30_000;
const TS_WINDOW_SECS = 30;
const CONN_CLEANUP_MS = 5_000;

export interface ConnectOptions {
  serverUrl: string;
  rtcConfiguration?: RTCConfiguration;
  /** Provide an existing key pair instead of generating a fresh one. */
  keyPair?: CryptoKeyPair;
  /**
   * Called after offer signature and timestamp verification, before a
   * PeerConnection is created or an answer sent. Return false to silently
   * drop the offer — no response is sent to the dialer, to avoid leaking
   * whether the key is active. If unset, all incoming connections are dropped.
   */
  acceptConnection?: (remotePublicKey: CryptoKey) => boolean | Promise<boolean>;
  /**
   * Called when an incoming offer has been verified and accepted, after
   * setRemoteDescription but before the answer is created. Wire ondatachannel
   * and media track handlers here. The PC may still be closed by the library
   * if a subsequent ICE candidate fails auth.
   */
  onIncoming?: (pc: RTCPeerConnection, remotePublicKey: CryptoKey) => void;
}

export type DialFailureCode =
  | "peer-not-connected"
  | "auth-failed"
  | "signaling-failed";

export class DialError extends Error {
  readonly code: DialFailureCode;
  readonly cause?: unknown;

  constructor(code: DialFailureCode, message: string, cause?: unknown) {
    super(message);
    this.name = "DialError";
    this.code = code;
    this.cause = cause;
  }
}

export type DialSetup = (pc: RTCPeerConnection) => void | Promise<void>;

/** Options for a single dial attempt. Mirrors the fetch init pattern. */
export interface DialInit {
  /** Abort the dial. Use AbortSignal.timeout(ms) for timeouts. */
  signal?: AbortSignal;
}

// Wire format sent through the relay.
// base64url(JSON) keeps the payload newline-free for SSE framing.
type WireMessage = {
  from: string; // base64url sender pubkey
  data: string; // offer SDP | answer SDP | JSON(RTCIceCandidateInit)
  challenge: string; // base64url(random[32]), set by dialer, echoed in all replies
  ts?: string; // base64url(uint64 unix seconds, big-endian) — offers and answers only
  sig: string; // signature — see crypto.ts for payload construction
};

type DialSettler = {
  resolve: () => void;
  reject: (err: unknown) => void;
};

// Session holds the state for one active peer connection, keyed by
// "pubkey:challengeB64". Outbound connections set offerSdp and settler;
// inbound connections leave them undefined.
type Session = {
  pc: RTCPeerConnection;
  offerSdp?: string; // set for outbound dials, used to verify the answer
  settler?: DialSettler; // set for outbound dials awaiting authentication
};

function pack(msg: WireMessage): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(msg)));
}

function unpack(s: string): WireMessage | null {
  try {
    const obj = JSON.parse(new TextDecoder().decode(base64UrlDecode(s)));
    if (
      typeof obj?.from === "string" &&
      typeof obj?.data === "string" &&
      typeof obj?.challenge === "string" &&
      typeof obj?.sig === "string"
    ) {
      return obj as WireMessage;
    }
    return null;
  } catch {
    return null;
  }
}

/** Returns current unix time as an 8-byte big-endian Uint8Array. */
function currentTs(): Uint8Array {
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(
    0,
    BigInt(Math.floor(Date.now() / 1000)),
    false,
  );
  return ts;
}

/**
 * Parses and validates a `ts` field from a WireMessage.
 * Returns the raw bytes if the timestamp is within TS_WINDOW_SECS, null otherwise.
 */
function parseTs(tsField: string | undefined): Uint8Array | null {
  if (!tsField) return null;
  try {
    const bytes = base64UrlDecode(tsField);
    if (bytes.length !== 8) return null;
    const ts = Number(
      new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, false),
    );
    if (Math.abs(Math.floor(Date.now() / 1000) - ts) > TS_WINDOW_SECS)
      return null;
    return bytes;
  } catch {
    return null;
  }
}

export class ConnectClient {
  /**
   * Base64url-encoded Ed25519 public key identifying this client on the relay.
   * Share this so others can reach you via dial().
   */
  readonly pubkey: string;

  private readonly keyPair: CryptoKeyPair;
  private readonly options: {
    serverUrl: string;
    rtcConfiguration: RTCConfiguration;
    acceptConnection?: (remotePublicKey: CryptoKey) => boolean | Promise<boolean>;
    onIncoming?: (pc: RTCPeerConnection, remotePublicKey: CryptoKey) => void;
  };
  // Composite key "pubkey:challengeB64" → Session. Including the challenge
  // allows a single remote pubkey to have multiple simultaneous connections.
  private readonly sessions = new Map<string, Session>();
  private closed = false;
  private readonly abort = new AbortController();

  private constructor(
    keyPair: CryptoKeyPair,
    options: ConnectOptions,
    pubkey: string,
  ) {
    this.keyPair = keyPair;
    this.pubkey = pubkey;
    this.options = {
      serverUrl: options.serverUrl.replace(/\/$/, ""),
      rtcConfiguration: options.rtcConfiguration ?? {
        iceServers: DEFAULT_ICE_SERVERS,
      },
      acceptConnection: options.acceptConnection,
      onIncoming: options.onIncoming,
    };
  }

  /**
   * Create a ConnectClient, generating a fresh Ed25519 identity (or using the
   * provided keyPair), then open an authenticated SSE stream.
   */
  static async create(options: ConnectOptions): Promise<ConnectClient> {
    let keyPair = options.keyPair;
    if (!keyPair) {
      keyPair = await crypto.subtle.generateKey("Ed25519", false, [
        "sign",
        "verify",
      ]);
    }
    const raw = new Uint8Array(
      await crypto.subtle.exportKey("raw", keyPair.publicKey),
    );
    const pubkey = base64UrlEncode(raw);
    const client = new ConnectClient(keyPair, options, pubkey);
    void client.runSSE();
    return client;
  }

  /**
   * Open a connection to the peer identified by `remotePublicKey`.
   *
   * setup is called before the first offer is created; add data channels,
   * media tracks, and event handlers there. Resolves after a verified answer
   * is applied; the returned PeerConnection may still be ICE/DTLS connecting.
   *
   * Pass `{ signal: AbortSignal.timeout(ms) }` to impose a dial timeout.
   */
  async dial(
    remotePublicKey: CryptoKey,
    setup: DialSetup,
    init?: DialInit,
  ): Promise<RTCPeerConnection> {
    const signal = init?.signal;
    if (signal?.aborted) {
      throw new DialError("signaling-failed", "dial aborted", signal.reason);
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const pc = new RTCPeerConnection(this.options.rtcConfiguration);
    let settle!: DialSettler;
    const authenticated = new Promise<void>((resolve, reject) => {
      settle = { resolve, reject };
    });

    const remotePubkey = await this.keyToString(remotePublicKey);
    const key = this.sessionKey(remotePubkey, challenge);
    const session: Session = { pc, settler: settle };
    this.sessions.set(key, session);
    const releaseIce = this.wireIce(pc, remotePubkey, challenge);

    const onAbort = () =>
      settle.reject(new DialError("signaling-failed", "dial aborted", signal?.reason));
    signal?.addEventListener("abort", onAbort, { once: true });

    try {
      await setup(pc);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      session.offerSdp = offer.sdp!;
      const ts = currentTs();
      const answererPubkeyBytes = base64UrlDecode(remotePubkey);
      await this.postOffer(
        remotePubkey,
        offer.sdp!,
        challenge,
        ts,
        answererPubkeyBytes,
      );
      releaseIce();
      await authenticated;
      signal?.removeEventListener("abort", onAbort);
      return pc;
    } catch (e) {
      signal?.removeEventListener("abort", onAbort);
      const err = this.toDialError(e);
      this.closeSession(key, err);
      throw err;
    }
  }

  /** Close the SSE stream and all peer connections. */
  close() {
    this.closed = true;
    this.abort.abort();
    for (const { pc, settler } of this.sessions.values()) {
      settler?.reject(new DialError("signaling-failed", "client closed"));
      pc.close();
    }
    this.sessions.clear();
  }

  private sessionKey(pubkey: string, challenge: Uint8Array): string {
    return `${pubkey}:${base64UrlEncode(challenge)}`;
  }

  private async keyToString(key: CryptoKey): Promise<string> {
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    return base64UrlEncode(raw);
  }

  private stringToKey(s: string): Promise<CryptoKey> {
    return crypto.subtle.importKey("raw", base64UrlDecode(s), "Ed25519", true, [
      "verify",
    ]);
  }

  // Closes the session, optionally rejecting the settler with an error.
  // Safe to call with an error even if the settler has already fired.
  private closeSession(key: string, err?: unknown): void {
    const session = this.sessions.get(key);
    if (!session) return;
    if (err !== undefined) session.settler?.reject(err);
    session.pc.close();
    this.sessions.delete(key);
  }

  private toDialError(err: unknown): DialError {
    if (err instanceof DialError) return err;
    return new DialError("signaling-failed", "signaling failed", err);
  }

  private wireIce(
    pc: RTCPeerConnection,
    remotePubkey: string,
    challenge: Uint8Array,
  ): () => void {
    const pending: string[] = [];
    let released = false;

    pc.onicecandidate = ({ candidate }) => {
      if (!candidate) return;
      const candidateJson = JSON.stringify(candidate.toJSON());
      if (!released) {
        pending.push(candidateJson);
        return;
      }
      void this.postICE(remotePubkey, candidateJson, challenge).catch(() => {});
    };

    return () => {
      if (released) return;
      released = true;
      for (const candidateJson of pending) {
        void this.postICE(remotePubkey, candidateJson, challenge).catch(
          () => {},
        );
      }
      pending.length = 0;
    };
  }

  private async sign(payload: BufferSource): Promise<string> {
    const sig = await crypto.subtle.sign(
      "Ed25519",
      this.keyPair.privateKey,
      payload,
    );
    return base64UrlEncode(new Uint8Array(sig));
  }

  private async postOffer(
    remotePubkey: string,
    offerSdp: string,
    challenge: Uint8Array,
    ts: Uint8Array,
    answererPubkeyBytes: Uint8Array,
  ): Promise<void> {
    await this.send(remotePubkey, {
      from: this.pubkey,
      data: offerSdp,
      challenge: base64UrlEncode(challenge),
      ts: base64UrlEncode(ts),
      sig: await this.sign(
        offerPayload(challenge, ts, answererPubkeyBytes, offerSdp),
      ),
    });
  }

  private async postAnswer(
    remotePubkey: string,
    answerSdp: string,
    challenge: Uint8Array,
    offerSdp: string,
  ): Promise<void> {
    const ts = currentTs();
    await this.send(remotePubkey, {
      from: this.pubkey,
      data: answerSdp,
      challenge: base64UrlEncode(challenge),
      ts: base64UrlEncode(ts),
      sig: await this.sign(answerPayload(challenge, ts, offerSdp, answerSdp)),
    });
  }

  private async postICE(
    remotePubkey: string,
    candidateJson: string,
    challenge: Uint8Array,
  ): Promise<void> {
    await this.send(remotePubkey, {
      from: this.pubkey,
      data: candidateJson,
      challenge: base64UrlEncode(challenge),
      sig: await this.sign(icePayload(challenge, candidateJson)),
    });
  }

  private async send(remotePubkey: string, msg: WireMessage): Promise<void> {
    const resp = await fetch(`${this.options.serverUrl}/${remotePubkey}`, {
      method: "POST",
      body: pack(msg),
    });
    if (!resp.ok) {
      throw new DialError(
        resp.status === 404 ? "peer-not-connected" : "signaling-failed",
        `relay POST failed: ${resp.status}`,
      );
    }
  }

  private async dispatch(msg: WireMessage): Promise<void> {
    let challenge: Uint8Array;
    try {
      challenge = base64UrlDecode(msg.challenge);
      if (challenge.length !== 32) return;
    } catch {
      return;
    }

    const key = this.sessionKey(msg.from, challenge);
    const session = this.sessions.get(key);

    if (!session) {
      // No session for this pubkey+challenge: treat as a new offer.
      await this.handleOffer(msg, challenge);
      return;
    }

    // Follow local RTCPeerConnection state to distinguish answer vs ICE.
    // A known session without a remote description is waiting for its answer.
    if (!session.pc.remoteDescription) {
      let ok = false;
      try {
        ok =
          !!session.offerSdp &&
          (await this.handleAnswer(
            session.pc,
            msg,
            challenge,
            session.offerSdp,
          ));
      } catch (e) {
        this.closeSession(key, this.toDialError(e));
        return;
      }
      if (!ok) {
        this.closeSession(
          key,
          new DialError("auth-failed", "failed to authenticate answer"),
        );
      } else {
        session.settler?.resolve();
        session.settler = undefined;
      }
      return;
    }

    let iceOk = false;
    try {
      iceOk = await this.handleIce(session.pc, msg, challenge);
    } catch (e) {
      this.closeSession(key, this.toDialError(e));
      return;
    }
    if (!iceOk) {
      this.closeSession(
        key,
        new DialError("auth-failed", "failed to authenticate ICE candidate"),
      );
    }
  }

  // Handles an incoming offer: verifies timestamp, signature, and recipient
  // binding; calls acceptConnection; creates PC; calls onIncoming; sends answer.
  private async handleOffer(
    msg: WireMessage,
    challenge: Uint8Array,
  ): Promise<void> {
    const ts = parseTs(msg.ts);
    if (!ts) return;

    const ownPubkeyBytes = base64UrlDecode(this.pubkey);
    let senderKey: CryptoKey;
    try {
      senderKey = await this.stringToKey(msg.from);
    } catch {
      return;
    }

    const valid = await crypto.subtle
      .verify(
        "Ed25519",
        senderKey,
        base64UrlDecode(msg.sig),
        offerPayload(challenge, ts, ownPubkeyBytes, msg.data),
      )
      .catch(() => false);
    if (!valid) return;

    if (this.options.acceptConnection) {
      const accepted = await Promise.resolve(
        this.options.acceptConnection(senderKey),
      ).catch(() => false);
      if (!accepted) return;
    } else {
      return;
    }

    const incoming = new RTCPeerConnection(this.options.rtcConfiguration);
    const releaseIce = this.wireIce(incoming, msg.from, challenge);
    const key = this.sessionKey(msg.from, challenge);
    this.sessions.set(key, { pc: incoming });

    try {
      await incoming.setRemoteDescription({ type: "offer", sdp: msg.data });
      this.options.onIncoming?.(incoming, senderKey);
      const answer = await incoming.createAnswer();
      await incoming.setLocalDescription(answer);
      await this.postAnswer(msg.from, answer.sdp!, challenge, msg.data);
      releaseIce();
    } catch (e) {
      this.closeSession(key);
      throw e;
    }
  }

  // Handles an incoming answer: verifies timestamp and signature (covering the
  // dialer's own offer SDP), then applies the remote description.
  // Returns false on any verification failure — the caller closes the PC.
  private async handleAnswer(
    pc: RTCPeerConnection,
    msg: WireMessage,
    challenge: Uint8Array,
    offerSdp: string,
  ): Promise<boolean> {
    const ts = parseTs(msg.ts);
    if (!ts) return false;

    let senderKey: CryptoKey;
    try {
      senderKey = await this.stringToKey(msg.from);
    } catch {
      return false;
    }

    const valid = await crypto.subtle
      .verify(
        "Ed25519",
        senderKey,
        base64UrlDecode(msg.sig),
        answerPayload(challenge, ts, offerSdp, msg.data),
      )
      .catch(() => false);
    if (!valid) return false;

    await pc.setRemoteDescription({ type: "answer", sdp: msg.data });
    return true;
  }

  // Handles an incoming ICE candidate: verifies signature, then adds the candidate.
  // Returns false on any verification failure — the caller closes the PC.
  private async handleIce(
    pc: RTCPeerConnection,
    msg: WireMessage,
    challenge: Uint8Array,
  ): Promise<boolean> {
    let senderKey: CryptoKey;
    try {
      senderKey = await this.stringToKey(msg.from);
    } catch {
      return false;
    }

    const valid = await crypto.subtle
      .verify(
        "Ed25519",
        senderKey,
        base64UrlDecode(msg.sig),
        icePayload(challenge, msg.data),
      )
      .catch(() => false);
    if (!valid) return false;

    await pc
      .addIceCandidate(JSON.parse(msg.data) as RTCIceCandidateInit)
      .catch(() => {
        /* WebRTC rejects candidates that arrive before setRemoteDescription;
           this is benign during race conditions at connection setup. */
      });
    return true;
  }

  // Resolves after ms, or immediately if the client is closed.
  private sleep(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const t = setTimeout(resolve, ms);
      this.abort.signal.addEventListener(
        "abort",
        () => {
          clearTimeout(t);
          resolve();
        },
        { once: true },
      );
    });
  }

  private async runSSE(): Promise<void> {
    const path = `/${this.pubkey}`;
    const dec = new TextDecoder();
    let backoff = RECONNECT_BASE_MS;

    const cleanupId = setInterval(() => {
      for (const [key, session] of this.sessions) {
        if (
          session.pc.connectionState === "failed" ||
          session.pc.connectionState === "closed"
        ) {
          session.settler?.reject(
            new DialError(
              "signaling-failed",
              "peer connection closed before authentication",
            ),
          );
          session.pc.close();
          this.sessions.delete(key);
        }
      }
    }, CONN_CLEANUP_MS);
    this.abort.signal.addEventListener(
      "abort",
      () => clearInterval(cleanupId),
      { once: true },
    );

    while (!this.closed) {
      try {
        const tsBytes = currentTs();
        const sigBytes = new Uint8Array(
          await crypto.subtle.sign(
            "Ed25519",
            this.keyPair.privateKey,
            ssePayload(tsBytes),
          ),
        );
        const combined = new Uint8Array(72);
        combined.set(sigBytes, 0);
        combined.set(tsBytes, 64);

        const resp = await fetch(
          `${this.options.serverUrl}${path}?sig=${base64UrlEncode(combined)}`,
          { signal: this.abort.signal },
        );

        if (!resp.ok || !resp.body)
          throw new Error(`SSE connect failed: ${resp.status}`);

        backoff = RECONNECT_BASE_MS;

        const reader = resp.body.getReader();
        let buf = "";

        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let nl: number;
          while ((nl = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, nl).trimEnd();
            buf = buf.slice(nl + 1);
            if (line.startsWith("data: ")) {
              const msg = unpack(line.slice(6));
              // Process sequentially to preserve offer-before-candidate ordering.
              // Errors are isolated per message — a bad message must not reconnect the SSE.
              if (msg)
                await this.dispatch(msg).catch((e) =>
                  console.error("[signaling]", e),
                );
            }
          }
        }
      } catch (e: unknown) {
        if (
          this.closed ||
          (e instanceof DOMException && e.name === "AbortError")
        )
          return;
        backoff = Math.min(backoff * 2, RECONNECT_MAX_MS);
      }

      // Always delay before reconnecting — clean close or error — and add
      // jitter so two clients that share a key don't reconnect in lockstep.
      await this.sleep(backoff + Math.random() * 1000);
    }
  }
}
