/* ============================================================
   SecureVault UI — panels, drag&drop, API wiring, toasts
   ============================================================ */

const $ = (id) => document.getElementById(id);

/* Same-origin when served by FastAPI; fall back to the dev port. */
const API = location.protocol.startsWith("http")
  ? "" : "http://127.0.0.1:8000";

const fmtBytes = (n) => {
  if (n === 0) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
};
const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* ---------------- toasts ---------------- */

export function toast(msg, kind = "info", ms = 4200) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<span>${esc(msg)}</span>`;
  $("toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 320);
  }, ms);
}
window.toast = toast;

/* ---------------- scene boot ---------------- */

let sceneReady = false;
window.addEventListener("sv-scene-ready", () => { sceneReady = true; }, { once: true });

(async () => {
  try { await import("./scene.js"); } catch { /* scene failed — CSS bg remains */ }
  setTimeout(() => $("boot").classList.add("done"), 350);
})();

window.SVOnShardClick = (index) => {
  const f = lastSplit?.set?.fragments?.[index];
  if (f) toast(`Shard #${index + 1} — ${f.name} (${fmtBytes(f.bytes)})`, "info");
};

/* ---------------- health & stats ---------------- */

async function refreshHealth() {
  const chip = $("statusChip");
  try {
    const r = await fetch(`${API}/api/health`);
    if (!r.ok) throw new Error();
    const h = await r.json();
    chip.classList.add("online");
    chip.classList.remove("offline");
    $("statusText").textContent = `vault online · ${h.engine}`;
    $("statEngine").textContent = `Python v${h.version}`;
    const v = await fetch(`${API}/api/vault`).then((x) => x.json());
    $("statSets").textContent = v.sets.length;
    $("statShards").textContent = v.sets.reduce((a, s) => a + s.parts, 0);
  } catch {
    chip.classList.add("offline");
    chip.classList.remove("online");
    $("statusText").textContent = "vault offline — start the server";
    $("statEngine").textContent = "—";
  }
}
refreshHealth();
setInterval(refreshHealth, 12000);

/* ---------------- navigation ---------------- */

const panels = {
  split: $("panel-split"),
  merge: $("panel-merge"),
  vault: $("panel-vault"),
  cloud: $("panel-cloud"),
};

$("nav").addEventListener("click", (e) => {
  const btn = e.target.closest(".pill");
  if (!btn) return;
  document.querySelectorAll(".nav .pill").forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  Object.entries(panels).forEach(([k, el]) =>
    el.classList.toggle("hidden", k !== btn.dataset.panel));
  if (btn.dataset.panel === "vault") loadVault();
  if (btn.dataset.panel === "cloud") loadCloudPanel();
});

/* ---------------- storage destination ---------------- */

$("splitDestination").addEventListener("input", (e) => {
  const v = e.target.value.trim();
  $("destNote").textContent = v ? "custom folder" : "vault folder";
  $("destNote").style.color = v ? "var(--ok)" : "";
});

/* ---------------- slider fill helper ---------------- */

function paintRange(input) {
  const p = ((input.value - input.min) / (input.max - input.min)) * 100;
  input.style.setProperty("--fill", `${p}%`);
}

/* ================= SPLIT ================= */

let lastSplit = null;

const dropSplit = $("dropSplit");
const splitFileInput = $("splitFile");

function setSplitFile(file) {
  if (!file) return;
  const dt = new DataTransfer();
  dt.items.add(file);
  splitFileInput.files = dt.files;
  $("splitFileName").textContent = file.name;
  $("splitFileSize").textContent = fmtBytes(file.size);
  dropSplit.querySelector(".dz-idle").classList.add("hidden");
  $("splitFileChip").classList.remove("hidden");
}

function clearSplitFile() {
  splitFileInput.value = "";
  dropSplit.querySelector(".dz-idle").classList.remove("hidden");
  $("splitFileChip").classList.add("hidden");
}

dropSplit.addEventListener("click", (e) => {
  if (!e.target.closest(".icon-btn")) splitFileInput.click();
});
splitFileInput.addEventListener("change", () => setSplitFile(splitFileInput.files[0]));
$("splitFileClear").addEventListener("click", (e) => {
  e.stopPropagation();
  clearSplitFile();
});
["dragover", "dragenter"].forEach((ev) =>
  dropSplit.addEventListener(ev, (e) => { e.preventDefault(); dropSplit.classList.add("dragover"); }));
["dragleave", "drop"].forEach((ev) =>
  dropSplit.addEventListener(ev, (e) => { e.preventDefault(); dropSplit.classList.remove("dragover"); }));
dropSplit.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) setSplitFile(e.dataTransfer.files[0]);
});

/* sliders: n parts & k threshold */
const partsInput = $("parts");
const thrInput = $("threshold");

function syncThreshold() {
  const n = +partsInput.value;
  thrInput.max = n;
  if (+thrInput.value > n) thrInput.value = n;
  const k = +thrInput.value;

  $("partsOut").textContent = n;
  $("thrOut").textContent = k;
  $("thrK").textContent = k;
  $("thrN").textContent = n;
  $("thrHint").textContent = k < n
    ? `erasure coding + key splitting — any ${k} of ${n} shards rebuild it, ${n - k} may be lost`
    : "all shards are required — no redundancy (raise k below n for fault tolerance)";
  paintRange(partsInput);
  paintRange(thrInput);
}
partsInput.addEventListener("input", syncThreshold);
thrInput.addEventListener("input", syncThreshold);
syncThreshold();

$("splitEncrypt").addEventListener("change", (e) => {
  $("splitPassWrap").classList.toggle("hidden", !e.target.checked);
  $("encModeNote").textContent = e.target.checked ? "— scrypt KDF, unique IV per shard" : "";
});

$("splitBtn").addEventListener("click", async () => {
  const file = splitFileInput.files[0];
  if (!file) return toast("Choose a file to shatter first", "err");
  const password = $("splitPassword").value;
  if ($("splitEncrypt").checked && !password) return toast("Enter a master password", "err");

  const n = +partsInput.value;
  const k = +thrInput.value;

  const fd = new FormData();
  fd.append("file", file);
  fd.append("parts", n);
  fd.append("threshold", k);
  fd.append("mode", "auto");
  fd.append("password", password);
  fd.append("destination", $("splitDestination").value.trim());

  const btn = $("splitBtn");
  btn.disabled = true;
  btn.classList.add("busy");
  $("splitProgress").classList.remove("hidden");
  window.SVScene?.pulse();

  try {
    const r = await fetch(`${API}/api/split`, { method: "POST", body: fd });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Split failed");

    const set = data.set;
    lastSplit = data;
    const modeLabel = set.mode === "shamir" ? "Shamir key-splitting"
      : set.mode === "password" ? "password-protected (scrypt)" : "open shards";

    $("resultTitle").textContent =
      `${set.original} → ${set.parts} shards (any ${set.threshold} rebuild it)`;
    const where = set.location && set.location !== "vault"
      ? `stored in ${set.location}` : "stored in the managed vault";
    $("resultSub").textContent =
      `${fmtBytes(set.size)} · sha-256 ${esc(String(set.total_sha256 || "").slice(0, 16))}… · ${modeLabel} · ${where}`;

    const grid = $("fragGrid");
    grid.innerHTML = "";
    set.fragments.forEach((f, i) => {
      const card = document.createElement("div");
      card.className = "frag-card" + (set.mode === "shamir" && i < set.threshold ? " key-shard" : "");
      card.style.animationDelay = `${i * 0.05}s`;
      card.innerHTML = `
        <div class="frag-top">
          <span class="frag-num">${f.part}</span>
          <span class="frag-name" title="${esc(f.name)}">${esc(f.name)}</span>
          <a class="frag-dl" href="${API}${f.url}" download="${esc(f.name)}" title="download shard">↓</a>
        </div>
        <div class="frag-meta"><span>${fmtBytes(f.bytes)}</span>${f.sha256 ? `<span>#${esc(f.sha256.slice(0, 8))}</span>` : ""}</div>
        <div class="frag-badges">
          ${set.mode === "shamir" ? `<span class="badge ${i < set.threshold ? "share" : "plain"}">${i < set.threshold ? "key share" : "parity"}</span>` : ""}
          ${set.mode === "password" ? `<span class="badge lock">encrypted</span>` : ""}
          ${set.mode === "none" ? `<span class="badge plain">open</span>` : ""}
        </div>`;
      grid.appendChild(card);
    });

    $("splitResult").classList.remove("hidden");
    window.SVScene?.shatter(set.parts, set.threshold, set.mode);
    toast(data.message, "ok");
    refreshHealth();
  } catch (err) {
    toast(err.message, "err");
    window.SVScene?.fail();
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
    $("splitProgress").classList.add("hidden");
  }
});

$("downloadAll").addEventListener("click", async () => {
  const frags = lastSplit?.set?.fragments || [];
  for (const f of frags) {
    const a = document.createElement("a");
    a.href = `${API}${f.url}`;
    a.download = f.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    await new Promise((r) => setTimeout(r, 280));
  }
  toast(`Saving ${frags.length} shards…`, "info");
});

/* push the freshly split set to a cloud connection */
$("pushCloud").addEventListener("click", async () => {
  const set = lastSplit?.set;
  if (!set) return;
  const conns = await fetch(`${API}/api/cloud`).then((r) => r.json())
    .catch(() => ({ connections: [] }));
  const list = conns.connections || [];
  if (!list.length) {
    toast("No cloud connection yet — add one in the Cloud tab", "err");
    switchPanel("cloud");
    return;
  }
  const name = list.length === 1 ? list[0].name
    : prompt(`Push ${set.parts} shards to which connection?\n${list.map((c) => c.name).join("\n")}`);
  if (!name) return;
  try {
    const r = await fetch(`${API}/api/cloud/${encodeURIComponent(name)}/upload/${set.id}`,
      { method: "POST" });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Upload failed");
    toast(d.message, "ok");
  } catch (err) {
    toast(err.message, "err");
  }
});

function switchPanel(key) {
  document.querySelectorAll(".nav .pill").forEach((p) =>
    p.classList.toggle("active", p.dataset.panel === key));
  Object.entries(panels).forEach(([k, el]) =>
    el.classList.toggle("hidden", k !== key));
}

/* ================= MERGE ================= */

const collected = [];      // inspected fragment headers

const dropMerge = $("dropMerge");
const mergeInput = $("mergeFiles");

dropMerge.addEventListener("click", () => mergeInput.click());
["dragover", "dragenter"].forEach((ev) =>
  dropMerge.addEventListener(ev, (e) => { e.preventDefault(); dropMerge.classList.add("dragover"); }));
["dragleave", "drop"].forEach((ev) =>
  dropMerge.addEventListener(ev, (e) => { e.preventDefault(); dropMerge.classList.remove("dragover"); }));
dropMerge.addEventListener("drop", (e) => ingestShards(e.dataTransfer.files));
mergeInput.addEventListener("change", () => ingestShards(mergeInput.files));

function renderCollected() {
  const grid = $("mergeGrid");
  grid.innerHTML = "";
  collected.forEach((c, i) => {
    const isKey = c.mode === "shamir" && c.share && c.share.x <= c.threshold;
    const card = document.createElement("div");
    card.className = "frag-card" + (isKey ? " key-shard" : "");
    card.style.animationDelay = `${i * 0.04}s`;
    card.innerHTML = c.error ? `
      <div class="frag-top"><span class="frag-num">?</span>
        <span class="frag-name">${esc(c.filename)}</span>
        <button class="frag-dl" data-rm="${i}" title="remove">✕</button></div>
      <div class="frag-badges"><span class="badge err">${esc(c.error)}</span></div>` : `
      <div class="frag-top"><span class="frag-num">${c.part}</span>
        <span class="frag-name" title="${esc(c.original)}">${esc(c.original)}</span>
        <button class="frag-dl" data-rm="${i}" title="remove">✕</button></div>
      <div class="frag-meta"><span>#${c.part} of ${c.parts}</span><span>${fmtBytes(c.payload_bytes)}</span></div>
      <div class="frag-badges">
        <span class="badge ${c.mode === "none" ? "plain" : c.mode === "password" ? "lock" : "share"}">${c.mode}</span>
        ${c.share ? `<span class="badge share">share x=${c.share.x}</span>` : ""}
      </div>`;
    grid.appendChild(card);
  });
  grid.querySelectorAll("[data-rm]").forEach((b) =>
    b.addEventListener("click", () => {
      collected.splice(+b.dataset.rm, 1);
      renderCollected();
    }));
  updateMergeMeter();
}

function updateMergeMeter() {
  const valid = collected.filter((c) => !c.error);
  const meter = $("thrMeter");
  if (!valid.length) { meter.classList.add("hidden"); $("mergeBtn").disabled = true; return; }
  meter.classList.remove("hidden");

  const k = Math.max(...valid.map((c) => c.threshold));
  const sameSet = valid.every((c) =>
    c.original === valid[0].original && c.parts === valid[0].parts);
  const uniqueParts = new Set(valid.map((c) => c.part)).size;

  $("thrNeed").textContent = k;
  $("thrCount").textContent = uniqueParts;
  const fill = $("thrFill");
  const pct = Math.min(100, (uniqueParts / k) * 100);
  fill.style.width = `${pct}%`;
  fill.classList.toggle("full", uniqueParts >= k);

  const encrypted = valid.some((c) => c.mode === "password");
  $("mergePassWrap").classList.toggle("hidden", !encrypted);

  const ready = sameSet && uniqueParts >= k && (!encrypted || $("mergePassword").value);
  $("mergeBtn").disabled = !ready;
  $("mergeBtn").querySelector(".cta-label").textContent =
    !sameSet ? "Shards from different sets"
      : uniqueParts < k ? `Need ${k - uniqueParts} more shard${k - uniqueParts > 1 ? "s" : ""}`
        : encrypted && !$("mergePassword").value ? "Enter the password"
          : `Reconstruct from ${uniqueParts} shards`;
}

$("mergePassword").addEventListener("input", updateMergeMeter);

async function ingestShards(fileList) {
  const files = [...fileList].filter((f) => f.size > 0);
  if (!files.length) return;
  const fd = new FormData();
  files.forEach((f) => fd.append("files", f));
  try {
    const r = await fetch(`${API}/api/inspect`, { method: "POST", body: fd });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Inspect failed");
    // headers arrive in the same order as the files — bind each File to its
    // header so the merge call uploads exactly the accepted shards
    let added = 0;
    data.fragments.forEach((f, i) => {
      const dup = !f.error && collected.some((c) =>
        !c.error && c.original === f.original && c.part === f.part);
      if (!dup) {
        collected.push({ ...f, file: files[i] });
        added++;
      }
    });
    renderCollected();
    const okCount = data.fragments.filter((f) => !f.error).length;
    if (okCount) window.SVScene?.pulse();
    if (added) toast(`${added} shard${added > 1 ? "s" : ""} accepted`, "ok", 2600);
    data.fragments.filter((f) => f.error).forEach((f) => toast(f.error, "err"));
  } catch (err) {
    toast(err.message, "err");
  }
}

$("mergeBtn").addEventListener("click", async () => {
  const fd = new FormData();
  collected.filter((c) => !c.error && c.file).forEach((c) => fd.append("files", c.file));
  fd.append("password", $("mergePassword").value);

  const btn = $("mergeBtn");
  btn.disabled = true;
  btn.classList.add("busy");
  $("mergeProgress").classList.remove("hidden");
  window.SVScene?.pulse();

  try {
    const r = await fetch(`${API}/api/merge`, { method: "POST", body: fd });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || "Reconstruction failed");

    const res = data.result;
    $("mergeTitle").textContent = `${res.original} reconstructed`;
    $("mergeSub").textContent =
      `${fmtBytes(res.size)} from ${res.fragments_used}/${res.parts} shards · sha-256 ${res.total_sha256.slice(0, 20)}…`;
    $("mergeIntegrity").className = `integrity ${res.integrity === "verified" ? "ok" : "bad"}`;
    $("mergeIntegrity").innerHTML = res.integrity === "verified"
      ? "✔ sha-256 integrity VERIFIED — byte-perfect reconstruction"
      : "✕ integrity MISMATCH — fragments may be corrupted";
    $("mergeDownload").href = `${API}${res.download}`;
    $("mergeResult").classList.remove("hidden");

    window.SVScene?.assemble();
    toast(data.message, "ok");
    refreshHealth();
  } catch (err) {
    toast(err.message, "err");
    window.SVScene?.fail();
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
    $("mergeProgress").classList.add("hidden");
  }
});

/* ================= VAULT ================= */

async function loadVault() {
  try {
    const [v, a] = await Promise.all([
      fetch(`${API}/api/vault`).then((r) => r.json()),
      fetch(`${API}/api/audit`).then((r) => r.json()),
    ]);

    const sets = $("vaultSets");
    sets.innerHTML = v.sets.length ? "" : '<p class="empty">no fragment sets yet — shatter something</p>';
    v.sets.forEach((s) => {
      const el = document.createElement("div");
      el.className = "vault-item";
      el.innerHTML = `
        <div class="vi-top">
          <span class="vi-name" title="${esc(s.original)}">${esc(s.original)}</span>
          <div class="vi-actions">
            <button class="icon-btn" data-push-set="${s.id}" title="push shards to cloud">☁</button>
            <button class="icon-btn" data-del-set="${s.id}" title="destroy set">🗑</button>
          </div>
        </div>
        <div class="vi-sub">
          <span>${s.threshold} of ${s.parts}</span><span>·</span>
          <span>${fmtBytes(s.size)}</span><span>·</span>
          <span>${esc(s.mode)}</span><span>·</span>
          ${s.cloud ? `<span class="badge share">☁ ${esc(s.cloud.connection)}</span><span>·</span>` : ""}
          <span>${esc(s.created)}</span>
        </div>
        <div class="vi-fragments">
          ${s.fragments.map((f) =>
            `<a class="vf-chip ${f.present === false ? "missing" : ""}" href="${API}${f.url}" download="${esc(f.name)}">⬡${f.part}</a>`).join("")}
        </div>`;
      sets.appendChild(el);
    });

    const merged = $("vaultMerged");
    merged.innerHTML = v.merged.length ? "" : '<p class="empty">nothing reconstructed yet</p>';
    v.merged.forEach((m) => {
      const el = document.createElement("div");
      el.className = "vault-item";
      el.innerHTML = `
        <div class="vi-top">
          <span class="vi-name" title="${esc(m.name)}">${esc(m.name)}</span>
          <div class="vi-actions">
            <a class="icon-btn" href="${API}${m.url}" download="${esc(m.name)}" title="download" style="text-decoration:none">↓</a>
            <button class="icon-btn" data-del-merged="${esc(m.name)}" title="delete">🗑</button>
          </div>
        </div>
        <div class="vi-sub"><span>${fmtBytes(m.size)}</span><span>·</span><span>${esc(m.created)}</span></div>`;
      merged.appendChild(el);
    });

    const audit = $("auditList");
    audit.innerHTML = a.entries.length ? "" : '<p class="empty">no activity recorded</p>';
    a.entries.slice(0, 14).forEach((e) => {
      const row = document.createElement("div");
      row.className = "audit-row";
      row.innerHTML = `
        <span class="audit-ts">${esc((e.ts || "").replace("T", " ").slice(0, 19))}</span>
        <span class="audit-act ${e.action.includes("error") ? "err" : ""}">${esc(e.action)}</span>
        <span class="audit-detail" title="${esc(e.detail)}">${esc(e.detail)}</span>`;
      audit.appendChild(row);
    });

    sets.querySelectorAll("[data-del-set]").forEach((b) =>
      b.addEventListener("click", async () => {
        if (!confirm("Destroy this fragment set permanently?")) return;
        const r = await fetch(`${API}/api/vault/${b.dataset.delSet}`, { method: "DELETE" });
        const d = await r.json();
        toast(d.message || d.detail, r.ok ? "ok" : "err");
        loadVault(); refreshHealth();
      }));
    sets.querySelectorAll("[data-push-set]").forEach((b) =>
      b.addEventListener("click", async () => {
        const conns = await fetch(`${API}/api/cloud`).then((r) => r.json())
          .catch(() => ({ connections: [] }));
        const list = conns.connections || [];
        if (!list.length) {
          toast("No cloud connection yet — add one in the Cloud tab", "err");
          switchPanel("cloud");
          return;
        }
        const name = list.length === 1 ? list[0].name
          : prompt(`Push shards to which connection?\n${list.map((c) => c.name).join("\n")}`);
        if (!name) return;
        const r = await fetch(`${API}/api/cloud/${encodeURIComponent(name)}/upload/${b.dataset.pushSet}`,
          { method: "POST" });
        const d = await r.json();
        toast(d.message || d.detail, r.ok ? "ok" : "err");
        if (r.ok) loadVault();
      }));
    merged.querySelectorAll("[data-del-merged]").forEach((b) =>
      b.addEventListener("click", async () => {
        const r = await fetch(`${API}/api/vault/merged/${encodeURIComponent(b.dataset.delMerged)}`, { method: "DELETE" });
        const d = await r.json();
        toast(d.message || d.detail, r.ok ? "ok" : "err");
        loadVault();
      }));
  } catch {
    $("vaultSets").innerHTML = '<p class="empty">vault unreachable — is the server running?</p>';
  }
}

/* ================= CLOUD PANEL ================= */

let cloudProvider = "webdav";
let pickedRemoteKeys = new Set();
let remoteShards = [];

document.querySelectorAll("#cloudProvider .seg-btn").forEach((btn) =>
  btn.addEventListener("click", () => {
    cloudProvider = btn.dataset.provider;
    document.querySelectorAll("#cloudProvider .seg-btn").forEach((b) =>
      b.classList.toggle("active", b === btn));
    $("cloudWebdavFields").classList.toggle("hidden", cloudProvider !== "webdav");
    $("cloudS3Fields").classList.toggle("hidden", cloudProvider !== "s3");
  }));

function cloudCfgFromForm() {
  const cfg = { name: $("cloudName").value.trim(), provider: cloudProvider };
  if (cloudProvider === "webdav") {
    cfg.url = $("cloudUrl").value.trim();
    cfg.username = $("cloudUser").value.trim();
    cfg.password = $("cloudPass").value;
  } else {
    cfg.endpoint = $("cloudEndpoint").value.trim();
    cfg.bucket = $("cloudBucket").value.trim();
    cfg.region = $("cloudRegion").value.trim() || "us-east-1";
    cfg.access_key = $("cloudAccess").value.trim();
    cfg.secret_key = $("cloudSecret").value;
  }
  return cfg;
}

$("cloudTestBtn").addEventListener("click", async () => {
  const msg = $("cloudMsg");
  msg.className = "hint";
  msg.textContent = "testing connection…";
  try {
    const r = await fetch(`${API}/api/cloud?test=true`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cloudCfgFromForm()),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Connection failed");
    msg.className = "hint ok";
    msg.textContent = `✔ ${d.test.message} — saved`;
    toast(d.test.message, "ok");
    loadCloudPanel();
  } catch (err) {
    msg.className = "hint bad";
    msg.textContent = `✕ ${err.message}`;
    toast(err.message, "err");
  }
});

async function loadCloudPanel() {
  try {
    const d = await fetch(`${API}/api/cloud`).then((r) => r.json());
    const list = $("cloudConnList");
    list.innerHTML = (d.connections || []).length
      ? "" : '<p class="empty">no connections yet — add one above</p>';
    (d.connections || []).forEach((c) => {
      const el = document.createElement("div");
      el.className = "vault-item";
      const detail = c.provider === "s3"
        ? `s3 · ${esc(c.bucket)} @ ${esc(c.endpoint || "")}`
        : `webdav · ${esc(c.username)} @ ${esc(c.url)}`;
      el.innerHTML = `
        <div class="vi-top">
          <span class="vi-name">${esc(c.name)}</span>
          <div class="vi-actions">
            <button class="icon-btn" data-cloud-del="${esc(c.name)}" title="remove connection">🗑</button>
          </div>
        </div>
        <div class="vi-sub"><span>${detail}</span></div>`;
      list.appendChild(el);
    });
    list.querySelectorAll("[data-cloud-del]").forEach((b) =>
      b.addEventListener("click", async () => {
        const r = await fetch(`${API}/api/cloud/${encodeURIComponent(b.dataset.cloudDel)}`,
          { method: "DELETE" });
        const d = await r.json();
        toast(d.message || d.detail, r.ok ? "ok" : "err");
        loadCloudPanel();
      }));
    refreshCloudSelect();
  } catch {
    $("cloudConnList").innerHTML = '<p class="empty">vault unreachable</p>';
  }
}

async function refreshCloudSelect() {
  try {
    const d = await fetch(`${API}/api/cloud`).then((r) => r.json());
    const sel = $("cgConn");
    sel.innerHTML = (d.connections || []).map((c) =>
      `<option value="${esc(c.name)}">${esc(c.name)} (${esc(c.provider)})</option>`).join("");
  } catch { /* offline */ }
}

/* ---------------- gather shards from cloud (merge panel) ---------------- */

$("cgToggle").addEventListener("click", () => {
  $("cgBody").classList.toggle("hidden");
  $("cgChevron").classList.toggle("open");
  refreshCloudSelect();
});

$("cgList").addEventListener("click", async () => {
  const conn = $("cgConn").value;
  if (!conn) return toast("Add a cloud connection first", "err");
  const box = $("cgResults");
  box.innerHTML = '<p class="empty">listing remote shards…</p>';
  try {
    const d = await fetch(`${API}/api/cloud/${encodeURIComponent(conn)}/list`)
      .then((r) => r.json());
    if (!d.fragments) throw new Error("listing failed");
    remoteShards = d.fragments;
    pickedRemoteKeys = new Set();

    // group by set id
    const bySet = {};
    remoteShards.forEach((f) => { (bySet[f.set] = bySet[f.set] || []).push(f); });

    box.innerHTML = "";
    Object.entries(bySet).forEach(([sid, frags]) => {
      const head = document.createElement("p");
      head.className = "hint";
      head.style.margin = "4px 0 2px";
      head.textContent = `set ${sid} — ${frags.length} shards`;
      box.appendChild(head);
      frags.forEach((f) => {
        const row = document.createElement("div");
        row.className = "cg-row";
        row.innerHTML = `<span>⬡</span><span>${esc(f.name)}</span><span class="cg-size">${fmtBytes(f.size)}</span>`;
        row.addEventListener("click", () => {
          if (pickedRemoteKeys.has(f.key)) pickedRemoteKeys.delete(f.key);
          else pickedRemoteKeys.add(f.key);
          row.classList.toggle("picked");
          $("cgMergeBtn").disabled = pickedRemoteKeys.size === 0;
        });
        box.appendChild(row);
      });
    });
    if (!remoteShards.length) box.innerHTML = '<p class="empty">no shards pushed to this connection yet</p>';
    refreshCloudSelect();
  } catch (err) {
    box.innerHTML = `<p class="empty">${esc(err.message)}</p>`;
  }
});

$("cgMergeBtn").addEventListener("click", async () => {
  const conn = $("cgConn").value;
  if (!conn || !pickedRemoteKeys.size) return;
  const btn = $("cgMergeBtn");
  btn.disabled = true;
  btn.classList.add("busy");
  window.SVScene?.pulse();
  try {
    const r = await fetch(`${API}/api/cloud/${encodeURIComponent(conn)}/merge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keys: [...pickedRemoteKeys], password: $("mergePassword").value }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Cloud reconstruction failed");

    const res = d.result;
    $("mergeTitle").textContent = `${res.original} reconstructed (from cloud)`;
    $("mergeSub").textContent =
      `${fmtBytes(res.size)} from ${res.fragments_used}/${res.parts} remote shards · sha-256 ${res.total_sha256.slice(0, 20)}…`;
    $("mergeIntegrity").className = `integrity ${res.integrity === "verified" ? "ok" : "bad"}`;
    $("mergeIntegrity").innerHTML = res.integrity === "verified"
      ? `✔ fetched ${res.fragments_used} shards from '${esc(conn)}' — integrity VERIFIED`
      : "✕ integrity MISMATCH";
    $("mergeDownload").href = `${API}${res.download}`;
    $("mergeResult").classList.remove("hidden");
    window.SVScene?.assemble();
    toast(d.message, "ok");
    refreshHealth();
  } catch (err) {
    toast(err.message, "err");
    window.SVScene?.fail();
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
  }
});
