#!/usr/bin/env node

// browser-ping.mjs — open ping.html in the browser, report result to stdout.
//
// Usage:
//
//   # Listen mode — print pubkey and wait:
//   node browser-ping.mjs <serverURL>
//
//   # Dial mode — ping the remote pubkey and exit on pong:
//   node browser-ping.mjs <serverURL> <remotePubkey>

import http from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const [serverUrl, remotePubkey] = process.argv.slice(2);

if (!serverUrl) {
  console.error("usage: browser-ping.mjs serverURL [remote-pubkey]");
  process.exit(1);
}

const pagePath = resolve(__dirname, "ping.html");
const distDir = resolve(__dirname, "../dist");

const done = deferred();
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");

  if (req.method === "POST" && url.pathname === "/report") {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const report = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    log(`${report.status}: ${report.message || ""}`);
    res.writeHead(204).end();
    if (report.status === "ok") done.resolve();
    if (report.status === "fail") done.reject(new Error(report.message || "ping failed"));
    if (report.status === "listening") {
      // In listen mode, print the pubkey and keep the server running.
      console.log(report.message);
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/dist/index.js") {
    const js = await readFile(resolve(distDir, "index.js"));
    res.writeHead(200, { "content-type": "text/javascript" }).end(js);
    return;
  }

  if (req.method === "GET" && url.pathname === "/") {
    const html = await readFile(pagePath);
    res.writeHead(200, { "content-type": "text/html" }).end(html);
    return;
  }

  res.writeHead(404).end();
});

server.listen(0, "127.0.0.1", async () => {
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;

  let pageURL =
    `${base}/?server=${encodeURIComponent(serverUrl)}` +
    `&report=${encodeURIComponent(`${base}/report`)}` +
    `&client=${encodeURIComponent("/dist/index.js")}`;
  if (remotePubkey) {
    pageURL += `&remote=${encodeURIComponent(remotePubkey)}`;
  }

  log(`opening ${pageURL}`);
  openBrowser(pageURL);
});

if (remotePubkey) {
  try {
    await done.promise;
    server.close();
    process.exit(0);
  } catch (err) {
    server.close();
    console.error(err?.stack || err);
    process.exit(1);
  }
}
// In listen mode, run until killed.

function openBrowser(url) {
  const cmd = process.env.BROWSER || defaultBrowserCommand();
  const args =
    process.platform === "win32" && !process.env.BROWSER
      ? ["/c", "start", "", url]
      : [url];
  const child = spawn(cmd, args, {
    stdio: "ignore",
    detached: true,
  });
  child.unref();
}

function defaultBrowserCommand() {
  if (process.platform === "darwin") return "open";
  if (process.platform === "win32") return "cmd";
  return "xdg-open";
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function log(message) {
  console.error(`[browser-ping] ${new Date().toISOString().slice(11, 23)} ${message}`);
}
