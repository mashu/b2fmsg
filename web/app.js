import init, { WebExchange, composeMessage, readMessage } from "./pkg/b2fmsg.js?v=1";

const $ = (sel) => document.querySelector(sel);
const form = $("#connect");
const composer = $("#compose");
const logEl = $("#log");
const hint = $("#hint");
const statusEl = $("#status");
const rail = $("#rail");
const connectBtn = $("#connect-btn");
const abortBtn = $("#abort-btn");
const listEl = $("#list");
const reader = $("#reader");

const RELEASE = "https://github.com/mashu/b2fmsg/releases/latest/download";
const RELEASE_PAGE = "https://github.com/mashu/b2fmsg/releases/latest";
const SETTINGS_KEY = "b2fmsg.settings";
const REMEMBERED = ["call", "mode", "locator", "gateway", "via", "bridge"];
const STEPS = ["link", "login", "handshake", "transfer", "done"];

let exchange = null;
let socket = null;
let pollTimer = null;
let folder = "inbox";
let selected = null;
let blobUrls = [];

/* ---------- storage (IndexedDB: one record per message) ---------- */

const dbReady = new Promise((resolve, reject) => {
  const req = indexedDB.open("b2fmsg", 1);
  req.onupgradeneeded = () => req.result.createObjectStore("messages", { keyPath: "mid" });
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

async function tx(mode, fn) {
  const db = await dbReady;
  return new Promise((resolve, reject) => {
    const t = db.transaction("messages", mode);
    const result = fn(t.objectStore("messages"));
    t.oncomplete = () => resolve(result?.result);
    t.onerror = () => reject(t.error);
  });
}

const dbAll = () => tx("readonly", (s) => s.getAll());
const dbGet = (mid) => tx("readonly", (s) => s.get(mid));
const dbPut = (rec) => tx("readwrite", (s) => s.put(rec));
const dbDelete = (mid) => tx("readwrite", (s) => s.delete(mid));

function record(folderName, raw) {
  const m = readMessage(raw);
  return {
    mid: m.mid,
    folder: folderName,
    raw,
    time: m.time ?? Date.now(),
    subject: m.subject,
    from: m.from,
    to: [...m.to, ...m.cc].join(", "),
    size: m.size,
    files: m.files.length,
  };
}

/* ---------- helpers ---------- */

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function humanSize(n) {
  if (n < 1000) return `${n} B`;
  if (n < 1e6) return `${(n / 1000).toFixed(1)} kB`;
  return `${(n / 1e6).toFixed(1)} MB`;
}

function shortDate(ms) {
  const d = new Date(ms);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) {
    return d.toISOString().slice(11, 16) + "Z";
  }
  return d.toISOString().slice(0, 10);
}

function stamp() {
  return new Date().toISOString().slice(11, 19) + "Z";
}

function log(kind, text) {
  const line = document.createElement("div");
  line.className = kind;
  const marker = { tx: "›", rx: "‹", ok: "✓", error: "✗", warn: "!", mail: "←" }[kind] ?? "·";
  line.textContent = `${stamp()} ${marker} ${text}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function setStatus(state, text) {
  statusEl.dataset.state = state;
  statusEl.textContent = text;
}

function run(fn) {
  try {
    return fn();
  } catch (e) {
    console.error(e);
    log("error", e?.message || String(e));
    return null;
  }
}

/* ---------- the exchange rail ---------- */

function railReset() {
  rail.removeAttribute("data-result");
  for (const li of rail.children) li.removeAttribute("data-state");
}

function railAt(step) {
  const target = STEPS.indexOf(step);
  STEPS.forEach((name, i) => {
    const li = rail.querySelector(`[data-step="${name}"]`);
    if (i < target) li.dataset.state = "done";
    else if (i === target) li.dataset.state = step === "done" ? "done" : "active";
  });
}

function railFail() {
  const active = rail.querySelector('[data-state="active"]');
  if (active) active.dataset.state = "failed";
  rail.dataset.result = "failed";
}

function railFromLog(kind, text) {
  const current = STEPS.indexOf(rail.querySelector('[data-state="active"]')?.dataset.step);
  const reach = (step) => {
    if (STEPS.indexOf(step) > current) railAt(step);
  };
  if (text === "logged in" || kind === "ok") reach("handshake");
  else if (kind === "rx" && text.startsWith("[")) reach("handshake");
  else if (kind === "tx" && /^(FC|FF|FS|FQ|F>)/.test(text)) reach("transfer");
  else if (kind === "rx" && /^(FC|FF|FS|FQ)/.test(text)) reach("transfer");
}

/* ---------- mailbox view ---------- */

async function refresh() {
  const all = await dbAll();
  const counts = { inbox: 0, outbox: 0, sent: 0 };
  for (const r of all) counts[r.folder] = (counts[r.folder] ?? 0) + 1;
  for (const tab of document.querySelectorAll(".tab")) {
    const n = counts[tab.dataset.folder];
    tab.querySelector(".count").textContent = n ? n : "";
    tab.setAttribute("aria-selected", String(tab.dataset.folder === folder));
  }
  const rows = all.filter((r) => r.folder === folder).sort((a, b) => b.time - a.time);
  listEl.replaceChildren();
  if (rows.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = {
      inbox: "No mail yet. Connect to fetch messages waiting for you.",
      outbox: "Nothing waiting to go out. Write a message and it is sent on your next connection.",
      sent: "Messages move here once the other side confirms them.",
    }[folder];
    listEl.appendChild(li);
  }
  for (const r of rows) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "row";
    btn.setAttribute("aria-current", String(r.mid === selected));
    const who = document.createElement("span");
    who.className = "who";
    who.textContent = folder === "inbox" ? r.from : r.to;
    const subject = document.createElement("span");
    subject.className = "subject";
    subject.textContent = r.subject;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = `${shortDate(r.time)}  ${humanSize(r.size)}${r.files ? `  +${r.files}` : ""}`;
    btn.append(who, subject, meta);
    btn.addEventListener("click", () => openMessage(r.mid));
    li.appendChild(btn);
    listEl.appendChild(li);
  }
  if (selected && !rows.some((r) => r.mid === selected)) closeReader();
}

async function openMessage(mid) {
  const rec = await dbGet(mid);
  if (!rec) return;
  const m = run(() => readMessage(rec.raw));
  if (!m) return;
  revokeBlobs();
  selected = mid;
  reader.replaceChildren();
  const h = document.createElement("h2");
  h.textContent = m.subject;
  const dl = document.createElement("dl");
  const add = (label, value) => {
    if (!value) return;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    dl.append(dt, dd);
  };
  add("From", m.from);
  add("To", m.to.join(", "));
  add("Cc", m.cc.join(", "));
  add("Date", `${m.date} UTC`);
  add("Message ID", m.mid);
  const body = document.createElement("pre");
  body.textContent = m.body.replace(/\r\n/g, "\n");
  reader.append(h, dl, body);
  if (m.files.length) {
    const files = document.createElement("div");
    files.className = "files";
    for (const f of m.files) {
      const a = document.createElement("a");
      const url = URL.createObjectURL(new Blob([b64ToBytes(f.data)]));
      blobUrls.push(url);
      a.href = url;
      a.download = f.name;
      a.textContent = `${f.name} · ${humanSize(f.size)}`;
      files.appendChild(a);
    }
    reader.appendChild(files);
  }
  const actions = document.createElement("div");
  actions.className = "actions";
  const del = document.createElement("button");
  del.type = "button";
  del.className = "ghost";
  del.textContent = rec.folder === "outbox" ? "Delete from outbox" : "Delete";
  del.addEventListener("click", async () => {
    await dbDelete(mid);
    closeReader();
    refresh();
  });
  actions.appendChild(del);
  reader.appendChild(actions);
  reader.hidden = false;
  refresh();
}

function revokeBlobs() {
  for (const url of blobUrls) URL.revokeObjectURL(url);
  blobUrls = [];
}

function closeReader() {
  revokeBlobs();
  selected = null;
  reader.hidden = true;
  reader.replaceChildren();
}

/* ---------- compose ---------- */

async function queueMessage() {
  const files = [];
  for (const file of composer.files.files) {
    files.push({ name: file.name, data: bytesToB64(new Uint8Array(await file.arrayBuffer())) });
  }
  const call = form.call.value.trim().toUpperCase();
  if (!call) {
    log("error", "Enter your callsign first; it is the sender of the message.");
    form.call.focus();
    return;
  }
  const composed = run(() =>
    composeMessage({
      from: call,
      to: composer.to.value,
      cc: composer.cc.value,
      subject: composer.subject.value,
      body: composer.body.value,
      files,
    })
  );
  if (!composed) return;
  for (const w of composed.warnings) log("warn", w);
  await dbPut(record("outbox", composed.raw));
  log("info", `${composed.mid} is in the outbox; it goes out on your next connection`);
  composer.reset();
  composer.hidden = true;
  folder = "outbox";
  refresh();
}

/* ---------- exchange over the bridge ---------- */

function settingsUi() {
  const agw = form.mode.value === "agw";
  document.querySelectorAll(".agw-only").forEach((el) => el.classList.toggle("hidden", !agw));
  hint.textContent = agw
    ? "start Direwolf (AGW port 8000), then b2fmsg-bridge"
    : "start b2fmsg-bridge; it connects to server.winlink.org";
  connectBtn.textContent = exchange ? "Connected" : agw ? "Call gateway" : "Send and receive";
}

function saveSettings() {
  const data = {};
  for (const k of REMEMBERED) data[k] = form[k].value;
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(data));
}

function loadSettings() {
  try {
    const data = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    for (const k of REMEMBERED) if (data[k]) form[k].value = data[k];
  } catch {
    /* ignore corrupt settings */
  }
}

let chain = Promise.resolve();

/** Actions are applied strictly in order, even across awaits on storage. */
function apply(actions) {
  if (!actions) return;
  chain = chain.then(() => applyNow(actions)).catch((e) => log("error", e?.message || String(e)));
}

async function applyNow(actions) {
  for (const a of actions) {
    switch (a.type) {
      case "send":
        if (socket?.readyState !== WebSocket.OPEN) {
          log("error", "connection closed while sending");
          if (exchange) run(() => exchange.abort());
          finish();
          return;
        }
        socket.send(b64ToBytes(a.data));
        break;
      case "log":
        log(a.kind, a.text);
        railFromLog(a.kind, a.text);
        break;
      case "received": {
        const rec = run(() => record("inbox", a.raw));
        if (rec) {
          await dbPut(rec);
          log("mail", `${rec.from}: ${rec.subject}`);
        }
        break;
      }
      case "delivered":
      case "already_delivered": {
        const rec = await dbGet(a.mid);
        if (rec) await dbPut({ ...rec, folder: "sent" });
        log("ok", `${a.mid} ${a.type === "delivered" ? "delivered" : "was already delivered"}`);
        break;
      }
      case "deferred":
        log("warn", `${a.mid} deferred by the remote; it stays in the outbox`);
        break;
      case "close":
        closeSocket();
        break;
      case "done":
        if (a.ok) {
          railAt("done");
          rail.dataset.result = "ok";
          log("ok", a.text);
          setStatus("idle", "done");
        } else {
          railFail();
          log("error", a.text);
          setStatus("error", "failed");
        }
        finish();
        break;
    }
  }
  refresh();
}

function closeSocket() {
  if (socket) {
    socket.onclose = null;
    socket.close();
    socket = null;
  }
}

function finish() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  closeSocket();
  exchange?.free();
  exchange = null;
  connectBtn.disabled = false;
  abortBtn.disabled = true;
  form.querySelectorAll("input, select").forEach((el) => (el.disabled = false));
  settingsUi();
}

async function connect() {
  const mode = form.mode.value;
  const call = form.call.value.trim().toUpperCase();
  const base = form.bridge.value.trim().replace(/\/+(cms|agw)?\/*$/, "");
  if (!/^wss?:\/\//.test(base)) {
    log("error", "The bridge address starts with ws:// (for example ws://127.0.0.1:8765).");
    return;
  }
  saveSettings();
  const all = await dbAll();
  const options = {
    mode,
    call,
    password: form.password.value,
    locator: form.locator.value,
    gateway: form.gateway.value,
    via: form.via.value.split(",").map((s) => s.trim()).filter(Boolean),
    outbox: all.filter((r) => r.folder === "outbox").map((r) => r.raw),
    known: all.filter((r) => r.folder === "inbox").map((r) => r.mid),
  };
  exchange = run(() => new WebExchange(options));
  if (!exchange) return;

  railReset();
  railAt("link");
  setStatus("live", "connecting");
  connectBtn.disabled = true;
  abortBtn.disabled = false;
  form.querySelectorAll("input, select").forEach((el) => (el.disabled = true));
  const url = `${base}/${mode}`;
  log("info", `${call} → ${url} (${options.outbox.length} to send)`);

  socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  socket.onopen = () => {
    railAt("login");
    setStatus("live", "on air");
    apply(run(() => exchange.start()));
    pollTimer = setInterval(() => {
      if (exchange) apply(run(() => exchange.poll()));
    }, 1000);
  };
  socket.onmessage = (ev) => {
    if (!exchange) return;
    const bytes = typeof ev.data === "string" ? new TextEncoder().encode(ev.data) : new Uint8Array(ev.data);
    apply(run(() => exchange.onBytes(bytes)));
  };
  socket.onerror = () => {
    log("error", `Cannot reach the bridge at ${url}. Is b2fmsg-bridge running?`);
  };
  socket.onclose = (ev) => {
    socket = null;
    if (ev.reason) log("error", ev.reason);
    if (exchange) apply(run(() => exchange.onClosed()));
    else finish();
  };
}

/* ---------- downloads ---------- */

function setupDownloads() {
  const ua = navigator.userAgent || "";
  let p = { label: "Linux x86_64", tag: "linux-x86_64", exe: "" };
  if (/Windows/i.test(ua)) p = { label: "Windows x86_64", tag: "windows-x86_64", exe: ".exe" };
  else if (/Mac OS/i.test(ua)) p = { label: "macOS aarch64", tag: "macos-aarch64", exe: "" };
  $("#dl-bridge").href = `${RELEASE}/b2fmsg-bridge-${p.tag}${p.exe}`;
  $("#dl-bridge").textContent = `Download bridge for ${p.label}`;
  $("#dl-cli").href = `${RELEASE}/b2fmsg-${p.tag}${p.exe}`;
  $("#dl-all").href = RELEASE_PAGE;
  $("#dl-detect").textContent = `Detected ${p.label}`;
}

/* ---------- wiring ---------- */

function wire() {
  loadSettings();
  settingsUi();
  form.mode.addEventListener("change", settingsUi);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!exchange) connect();
  });
  abortBtn.addEventListener("click", () => {
    if (exchange) apply(run(() => exchange.abort()));
  });
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      folder = tab.dataset.folder;
      closeReader();
      refresh();
    });
  }
  $("#write-btn").addEventListener("click", () => {
    composer.hidden = false;
    composer.to.focus();
  });
  $("#discard-btn").addEventListener("click", () => {
    composer.reset();
    composer.hidden = true;
  });
  composer.addEventListener("submit", (ev) => {
    ev.preventDefault();
    queueMessage();
  });
}

setupDownloads();
try {
  await init();
  wire();
  await refresh();
  connectBtn.disabled = false;
  settingsUi();
  setStatus("idle", "ready");
} catch (e) {
  console.error(e);
  connectBtn.textContent = "Could not start";
  setStatus("error", "failed to load");
  log("error", `The page could not load its WebAssembly module: ${e?.message || e}`);
}
