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
  /** Provide an existing key pair instead of loading from IndexedDB. */
  keyPair?: CryptoKeyPair;
  /**
   * Called after offer signature and timestamp verification, before a
   * PeerConnection is created or an answer sent. Return false to silently
   * drop the offer — no response is sent to the dialer, to avoid leaking
   * whether the key is active.
   */
  acceptConnection?: (remotePublicKey: CryptoKey) => boolean | Promise<boolean>;
  /**
   * Called when an incoming offer has been verified and accepted, after
   * setLocalDescription but before the answer is sent. Wire ondatachannel
   * and media track handlers here. The PC may still be closed by the library
   * if a subsequent ICE candidate fails auth — "incoming" means a valid
   * authenticated offer arrived, not that a working P2P connection exists.
   */
  onIncoming?: (pc: RTCPeerConnection, remotePublicKey: CryptoKey) => void;
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
    keyPair: CryptoKeyPair;
    acceptConnection?: (
      remotePublicKey: CryptoKey,
    ) => boolean | Promise<boolean>;
    onIncoming?: (pc: RTCPeerConnection, remotePublicKey: CryptoKey) => void;
  };
  // Composite key "pubkey:challengeB64" → RTCPeerConnection. Including the
  // challenge allows a single remote pubkey to have multiple simultaneous
  // connections (each dial generates a fresh challenge).
  private readonly sessions = new Map<string, RTCPeerConnection>();
  private readonly sentOffers = new Map<string, string>();
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
      keyPair: keyPair,
      acceptConnection: options.acceptConnection,
      onIncoming: options.onIncoming,
    };
  }

  /**
   * Create a ConnectClient. Loads (or generates) a persistent Ed25519
   * identity from IndexedDB, then opens an authenticated SSE stream.
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
   * Returns a raw RTCPeerConnection. Add data channels or media tracks before
   * returning control to trigger SDP negotiation. The library closes the PC
   * if the answer or any ICE candidate fails auth verification.
   */
  dial(remotePublicKey: CryptoKey): RTCPeerConnection {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const pc = new RTCPeerConnection(this.options.rtcConfiguration);

    // Key export is the only async step. onnegotiationneeded fires as a task
    // after microtasks drain, so setupPromise is always resolved first.
    const setupPromise = this.keyToString(remotePublicKey).then(
      (remotePubkey) => {
        this.sessions.set(this.sessionKey(remotePubkey, challenge), pc);

        pc.onicecandidate = ({ candidate }) => {
          if (candidate) {
            void this.postICE(
              remotePubkey,
              JSON.stringify(candidate.toJSON()),
              challenge,
            );
          }
        };

        return remotePubkey;
      },
    );

    setupPromise.catch((err) => {
      pc.close();
      console.error("[signaling] dial setup failed:", err);
    });

    pc.onnegotiationneeded = async () => {
      try {
        const remotePubkey = await setupPromise;
        if (pc.remoteDescription) return;
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        const key = this.sessionKey(remotePubkey, challenge);
        this.sentOffers.set(key, offer.sdp!);
        const ts = currentTs();
        const answererPubkeyBytes = base64UrlDecode(remotePubkey);
        await this.postOffer(
          remotePubkey,
          offer.sdp!,
          challenge,
          ts,
          answererPubkeyBytes,
        );
      } catch (e) {
        console.error("[signaling] offer failed:", e);
      }
    };

    return pc;
  }

  /** Close the SSE stream and all peer connections. */
  close() {
    this.closed = true;
    this.abort.abort();
    for (const pc of this.sessions.values()) pc.close();
    this.sessions.clear();
    this.sentOffers.clear();
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

  // Creates a PC for the answerer side and wires ICE candidate signing.
  // The caller is responsible for storing it in sessions.
  private makePC(
    remotePubkey: string,
    challenge: Uint8Array,
  ): RTCPeerConnection {
    const pc = new RTCPeerConnection(this.options.rtcConfiguration);

    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        void this.postICE(
          remotePubkey,
          JSON.stringify(candidate.toJSON()),
          challenge,
        );
      }
    };

    return pc;
  }

  private async postOffer(
    remotePubkey: string,
    offerSdp: string,
    challenge: Uint8Array,
    ts: Uint8Array,
    answererPubkeyBytes: Uint8Array,
  ): Promise<void> {
    const sig = await crypto.subtle.sign(
      "Ed25519",
      this.keyPair.privateKey,
      offerPayload(challenge, ts, answererPubkeyBytes, offerSdp),
    );
    await this.send(remotePubkey, {
      from: this.pubkey,
      data: offerSdp,
      challenge: base64UrlEncode(challenge),
      ts: base64UrlEncode(ts),
      sig: base64UrlEncode(new Uint8Array(sig)),
    });
  }

  private async postAnswer(
    remotePubkey: string,
    answerSdp: string,
    challenge: Uint8Array,
    offerSdp: string,
  ): Promise<void> {
    const ts = currentTs();
    const sig = await crypto.subtle.sign(
      "Ed25519",
      this.keyPair.privateKey,
      answerPayload(challenge, ts, offerSdp, answerSdp),
    );
    await this.send(remotePubkey, {
      from: this.pubkey,
      data: answerSdp,
      challenge: base64UrlEncode(challenge),
      ts: base64UrlEncode(ts),
      sig: base64UrlEncode(new Uint8Array(sig)),
    });
  }

  private async postICE(
    remotePubkey: string,
    candidateJson: string,
    challenge: Uint8Array,
  ): Promise<void> {
    const sig = await crypto.subtle.sign(
      "Ed25519",
      this.keyPair.privateKey,
      icePayload(challenge, candidateJson),
    );
    await this.send(remotePubkey, {
      from: this.pubkey,
      data: candidateJson,
      challenge: base64UrlEncode(challenge),
      sig: base64UrlEncode(new Uint8Array(sig)),
    });
  }

  private async send(remotePubkey: string, msg: WireMessage): Promise<void> {
    await fetch(`${this.options.serverUrl}/${remotePubkey}`, {
      method: "POST",
      body: pack(msg),
    });
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
    const pc = this.sessions.get(key);

    if (!pc) {
      // No session for this pubkey+challenge: treat as a new offer.
      await this.handleOffer(msg, challenge);
      return;
    }

    // Follow local RTCPeerConnection state, not message shape. A known session
    // without a remote description is waiting for its answer; once the remote
    // description is set, subsequent messages for the session are ICE.
    if (!pc.remoteDescription) {
      const offerSdp = this.sentOffers.get(key);
      if (
        !offerSdp ||
        !(await this.handleAnswer(pc, msg, challenge, offerSdp))
      ) {
        pc.close();
        console.log("Failed to handle answer");
        this.sessions.delete(key);
        this.sentOffers.delete(key);
      }
      return;
    }

    if (!(await this.handleIce(pc, msg, challenge))) {
      pc.close();
      console.log("Closing because failed handleIce", msg);
      this.sessions.delete(key);
      this.sentOffers.delete(key);
    }
  }

  // Handles an incoming offer: verifies timestamp, signature, and recipient
  // binding; calls acceptConnection; creates PC; negotiates answer; calls onIncoming.
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
    }

    const incoming = this.makePC(msg.from, challenge);
    const key = this.sessionKey(msg.from, challenge);
    this.sessions.set(key, incoming);

    try {
      await incoming.setRemoteDescription({ type: "offer", sdp: msg.data });
      const answer = await incoming.createAnswer();
      await incoming.setLocalDescription(answer);

      this.options.onIncoming?.(incoming, senderKey);

      await this.postAnswer(msg.from, answer.sdp!, challenge, msg.data);
    } catch (e) {
      incoming.close();
      console.log("Closing because failed to set", e);
      this.sessions.delete(key);
      this.sentOffers.delete(key);
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
      .catch((e) => {
        console.log("Failed to verify:", e);
        return false;
      });
    if (!valid) return false;

    console.log("Valid", senderKey);

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
      for (const [key, pc] of this.sessions) {
        if (
          pc.connectionState === "failed" ||
          pc.connectionState === "closed"
        ) {
          this.sessions.delete(key);
          this.sentOffers.delete(key);
        }
      }
    }, CONN_CLEANUP_MS);
    this.abort.signal.addEventListener(
      "abort",
      () => clearInterval(cleanupId),
      {
        once: true,
      },
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
