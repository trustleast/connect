import { ConnectClient } from "connect-js";

const BASE32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE32_LOOKUP = new Uint8Array(256).fill(255);
for (let i = 0; i < BASE32_ALPHA.length; i++)
  BASE32_LOOKUP[BASE32_ALPHA.charCodeAt(i)] = i;

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0,
    value = 0,
    out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHA[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHA[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str: string): Uint8Array<ArrayBuffer> {
  str = str.toUpperCase();
  const out = new Uint8Array(Math.floor((str.length * 5) / 8));
  let bits = 0,
    value = 0,
    index = 0;
  for (const char of str) {
    const c = BASE32_LOOKUP[char.charCodeAt(0)];
    if (c === 255) continue;
    value = (value << 5) | c;
    bits += 5;
    if (bits >= 8) {
      out[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return new Uint8Array(out.buffer, 0, index);
}

async function keyToBase32(key: CryptoKey): Promise<string> {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return base32Encode(raw);
}

const SERVER_URL = "https://connect.peerwave.ai";
// const SERVER_URL = "http://localhost:8080";

const pubkeyEl = document.getElementById("pubkey")!;
const statusEl = document.getElementById("status")!;
const chatEl = document.getElementById("chat") as HTMLElement;
const messagesEl = document.getElementById("messages")!;
const msgInputEl = document.getElementById("msg-input") as HTMLInputElement;

let dc: RTCDataChannel | null = null;

const keyPair = await crypto.subtle.generateKey("Ed25519", false, [
  "sign",
  "verify",
]);

const client = await ConnectClient.create({
  serverUrl: SERVER_URL,
  keyPair,
  onIncoming: async (pc, remotePublicKey) => {
    const label = (await keyToBase32(remotePublicKey)).slice(0, 8) + "…";
    dbg("incoming from", label);
    setupPC(pc);
    pc.ondatachannel = ({ channel }) => {
      dbg("got data channel");
      attachDataChannel(channel);
    };
    dbg("auth ok with", label);
  },
});

// Display the pubkey as base32 (human-friendly), but the client uses base64url internally.
pubkeyEl.textContent = await keyToBase32(keyPair.publicKey);
setStatus("listening");

document
  .getElementById("connect-form")!
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const raw = (document.getElementById("peer-key") as HTMLInputElement).value
      .trim()
      .toUpperCase();
    // Input is base32 (human-friendly); import raw bytes directly as a CryptoKey.
    const peerKey = await crypto.subtle.importKey(
      "raw",
      base32Decode(raw),
      "Ed25519",
      true,
      ["verify"],
    );
    setStatus(`calling ${raw.slice(0, 8)}…`);
    const pc = client.dial(peerKey);
    setupPC(pc);
    attachDataChannel(pc.createDataChannel("chat"));
  });

document.getElementById("send-btn")!.addEventListener("click", () => {
  const text = msgInputEl.value.trim();
  if (!text || dc?.readyState !== "open") return;
  dc.send(text);
  addMsg("me", text);
  msgInputEl.value = "";
});

msgInputEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter")
    (document.getElementById("send-btn") as HTMLButtonElement).click();
});

function setupPC(pc: RTCPeerConnection) {
  pc.onicegatheringstatechange = () => dbg("gathering:", pc.iceGatheringState);
  pc.oniceconnectionstatechange = () => dbg("ice:", pc.iceConnectionState);
  pc.onsignalingstatechange = () => dbg("signaling:", pc.signalingState);
  pc.onconnectionstatechange = () => {
    dbg("connection:", pc.connectionState);
    setStatus(pc.connectionState);
  };
}

function attachDataChannel(channel: RTCDataChannel) {
  dc = channel;
  channel.onopen = () => {
    dbg("data channel open");
    setStatus("connected");
    chatEl.style.display = "block";
  };
  channel.onclose = () => dbg("data channel closed");
  channel.onerror = (e) =>
    dbg("data channel error:", (e as RTCErrorEvent).error?.message ?? e);
  channel.onmessage = ({ data }) => addMsg("peer", data as string);
}

function setStatus(s: string) {
  statusEl.textContent = s;
}

function addMsg(who: "me" | "peer", text: string) {
  const el = document.createElement("div");
  el.className = who;
  el.textContent = (who === "me" ? "> " : "< ") + text;
  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function dbg(...args: unknown[]) {
  console.log("[rtc]", ...args);
  const el = document.createElement("div");
  el.style.color = "#555";
  el.textContent = "# " + args.join(" ");
  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}
