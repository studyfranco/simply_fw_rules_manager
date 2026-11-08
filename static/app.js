"use strict";

/* ---------------------------------------------------------------------- *
 * Pure-JS SHA-256 / HMAC-SHA256 fallback for plain-HTTP LAN deployments.
 * ---------------------------------------------------------------------- */

function sha256Bytes(bytes) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const bitLen = bytes.length * 8;
  const withOne = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  withOne.set(bytes);
  withOne[bytes.length] = 0x80;
  const dv = new DataView(withOne.buffer);
  dv.setUint32(withOne.length - 8, Math.floor(bitLen / 0x100000000), false);
  dv.setUint32(withOne.length - 4, bitLen >>> 0, false);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < withOne.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => odv.setUint32(i * 4, v, false));
  return out;
}

function hmacSha256Fallback(keyBytes, messageBytes) {
  const blockSize = 64;
  let k = keyBytes.length > blockSize ? sha256Bytes(keyBytes) : keyBytes;
  const padded = new Uint8Array(blockSize);
  padded.set(k);
  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    oKeyPad[i] = padded[i] ^ 0x5c;
    iKeyPad[i] = padded[i] ^ 0x36;
  }
  const inner = new Uint8Array(blockSize + messageBytes.length);
  inner.set(iKeyPad);
  inner.set(messageBytes, blockSize);
  const innerHash = sha256Bytes(inner);
  const outer = new Uint8Array(blockSize + 32);
  outer.set(oKeyPad);
  outer.set(innerHash, blockSize);
  return sha256Bytes(outer);
}

async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const keyBytes = enc.encode(secret);
  const msgBytes = enc.encode(message);
  let digestBytes;
  if (globalThis.crypto && globalThis.crypto.subtle) {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, msgBytes);
    digestBytes = new Uint8Array(sig);
  } else {
    digestBytes = hmacSha256Fallback(keyBytes, msgBytes);
  }
  return Array.from(digestBytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function detectMountPrefix() {
  let p = window.location.pathname || "/";
  if (p.endsWith("/index.html")) p = p.slice(0, -"/index.html".length);
  if (p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

function normalizeSigningBase(rawOverride) {
  if (!rawOverride) return "";
  let s = rawOverride.trim();
  if (!s) return "";
  if (!s.startsWith("/")) s = "/" + s;
  while (s.endsWith("/")) s = s.slice(0, -1);
  if (s === "/api") return "";
  if (s.endsWith("/api")) s = s.slice(0, -"/api".length);
  return s;
}

class ApiClient {
  constructor(apiKey, signingSecret, apiBaseOverride) {
    this.apiKey = apiKey;
    this.signingSecret = signingSecret;
    this.requestBase = detectMountPrefix();
    this.signingBase = normalizeSigningBase(apiBaseOverride);
  }

  async request(method, path, bodyObj) {
    const body = bodyObj === undefined ? "" : JSON.stringify(bodyObj);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const canonical = `${method}\n${this.signingBase}${path}\n${timestamp}\n${body}`;
    const sigHex = await hmacSha256Hex(this.signingSecret, canonical);

    const headers = {
      "X-API-Key": this.apiKey,
      "X-Timestamp": timestamp,
      "X-Signature-256": "sha256=" + sigHex,
    };
    if (bodyObj !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    const res = await fetch(this.requestBase + path, {
      method,
      headers,
      body: bodyObj === undefined ? undefined : body,
    });

    if (res.status === 204) return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.validation = data.validation || null;
      throw err;
    }
    return data;
  }

  get(path) { return this.request("GET", path); }
  post(path, body) { return this.request("POST", path, body === undefined ? {} : body); }
  put(path, body) { return this.request("PUT", path, body); }
  patch(path, body) { return this.request("PATCH", path, body); }
  del(path) { return this.request("DELETE", path); }
}

/* ---------------------------------------------------------------------- *
 * Application state & helpers
 * ---------------------------------------------------------------------- */

let client = null;
let me = null;
let activeTab = "settings";
let cachedDockerDiscovery = null;
let cachedSettings = null;
let zoneFilterState = "";
let auditFilterState = { action: "", client_ip: "", api_key: "" };

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function toast(message, kind = "info") {
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = `toast toast-${kind}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function statusBadge(status) {
  const s = (status || "unknown").toLowerCase();
  if (s === "running") return `<span class="badge badge-running">RUNNING</span>`;
  if (s === "stopped" || s === "exited") return `<span class="badge badge-stopped">STOPPED</span>`;
  if (s === "missing") return `<span class="badge badge-missing">MISSING</span>`;
  return `<span class="badge badge-unknown">${escapeHtml(s.toUpperCase())}</span>`;
}

function linesToArray(text) {
  return String(text || "")
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function arrayToLines(arr) {
  return Array.isArray(arr) ? arr.join("\n") : "";
}

/* ---------------------------------------------------------------------- *
 * Session & Login
 * ---------------------------------------------------------------------- */

document.getElementById("login-api-base").value =
  localStorage.getItem("simply_fw_rules_manager_api_base") || "";

const SESSION_STORAGE_KEY_PREFIX = "simply_fw_rules_manager_session_";

function saveSessionCredentials(apiKey, signingSecret) {
  try {
    sessionStorage.setItem(SESSION_STORAGE_KEY_PREFIX + "api_key", apiKey);
    sessionStorage.setItem(SESSION_STORAGE_KEY_PREFIX + "signing_secret", signingSecret);
  } catch {
    // Ignore storage quota / private mode errors
  }
}

function loadSessionCredentials() {
  try {
    const apiKey = sessionStorage.getItem(SESSION_STORAGE_KEY_PREFIX + "api_key");
    const signingSecret = sessionStorage.getItem(SESSION_STORAGE_KEY_PREFIX + "signing_secret");
    return apiKey && signingSecret ? { apiKey, signingSecret } : null;
  } catch {
    return null;
  }
}

function clearSessionCredentials() {
  try {
    sessionStorage.removeItem(SESSION_STORAGE_KEY_PREFIX + "api_key");
    sessionStorage.removeItem(SESSION_STORAGE_KEY_PREFIX + "signing_secret");
  } catch {
    // Ignore
  }
}

function describeTier(profile) {
  if (profile.is_master) return { label: "Master", title: "Full administrative key" };
  if (profile.can_manage_keys) return { label: "Parent", title: "Can delegate sub-keys" };
  return { label: "Sub-Key", title: "Scoped operational key" };
}

async function attemptSignIn(apiKey, signingSecret) {
  const apiBase = document.getElementById("login-api-base").value.trim();
  localStorage.setItem("simply_fw_rules_manager_api_base", apiBase);

  client = new ApiClient(apiKey, signingSecret, apiBase);
  me = await client.get("/api/auth/me");
  saveSessionCredentials(apiKey, signingSecret);

  document.getElementById("identity-name").textContent = `${me.name} (${me.prefix}…)`;
  const tier = describeTier(me);
  const badge = document.getElementById("current-key-tier") || document.getElementById("identity-badge");
  if (badge) {
    badge.textContent = tier.label;
    badge.title = tier.title;
    badge.className = `badge badge-tier ${tier.tier === 'master' ? 'badge-master' : 'badge-daughter'}`;
  }

  document.getElementById("keys-tab-btn")?.classList.toggle("hidden", !(me.is_master || me.can_manage_keys));
  document.getElementById("system-settings-tab-btn")?.classList.toggle("hidden", !me.is_master);
  document.getElementById("audit-tab-btn")?.classList.toggle("hidden", !me.is_master);

  document.getElementById("login-error").classList.add("hidden");
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("dashboard-container").classList.remove("hidden");

  await loadTab(activeTab);
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const apiKey = document.getElementById("login-api-key").value.trim();
  const signingSecret = document.getElementById("login-signing-secret").value.trim();
  const errEl = document.getElementById("login-error");
  errEl.classList.add("hidden");
  try {
    await attemptSignIn(apiKey, signingSecret);
  } catch (err) {
    errEl.textContent = "Authentication failed: " + err.message;
    errEl.classList.remove("hidden");
  }
});

const onLogout = () => {
  clearSessionCredentials();
  client = null;
  me = null;
  document.getElementById("dashboard-container").classList.add("hidden");
  document.getElementById("login-screen").classList.remove("hidden");
};
document.getElementById("btn-logout")?.addEventListener("click", onLogout);
document.getElementById("logout-btn")?.addEventListener("click", onLogout);

const onRefresh = () => loadTab(activeTab);
document.getElementById("btn-refresh")?.addEventListener("click", onRefresh);
document.getElementById("refresh-btn")?.addEventListener("click", onRefresh);

/* ---------------------------------------------------------------------- *
 * Global Top Bar Actions (Generate / Reload / Generate & Apply)
 * ---------------------------------------------------------------------- */

document.getElementById("btn-generate-files").addEventListener("click", async () => {
  try {
    const res = await client.post("/api/firewall/generate");
    toast(
      `Fichiers générés dans ${res.bundle.output_dir} (${res.bundle.active_docker_inter_rules} flux Docker actifs, ${res.bundle.skipped_docker_inter_rules} inactifs ignorés)`,
      "success"
    );
    if (activeTab === "deploy") await renderDeployTab();
  } catch (err) {
    toast("Erreur génération: " + err.message, "error");
  }
});

document.getElementById("btn-reload-fw").addEventListener("click", async () => {
  try {
    const res = await client.post("/api/firewall/reload");
    toast(`Firewall rechargé via simply_hook_executor (${res.hook_name}, HTTP ${res.status_code})`, "success");
  } catch (err) {
    toast("Erreur reload firewall: " + err.message, "error");
  }
});

document.getElementById("btn-generate-and-reload").addEventListener("click", async () => {
  try {
    const res = await client.post("/api/firewall/generate-and-reload");
    toast(
      `Généré (${res.files_written.length} fichiers) & appliqué via '${res.hook_result.hook_name}' (HTTP ${res.hook_result.status_code})`,
      "success"
    );
    if (activeTab === "deploy") await renderDeployTab();
  } catch (err) {
    toast("Erreur Générer & Appliquer: " + err.message, "error");
  }
});

/* ---------------------------------------------------------------------- *
 * Tab Navigation
 * ---------------------------------------------------------------------- */

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.classList.toggle("active", b === btn);
      b.setAttribute("aria-selected", b === btn ? "true" : "false");
    });
    document.querySelectorAll(".tab-panel").forEach((p) => {
      p.classList.toggle("active", p.id === "tab-" + tab);
    });
    activeTab = tab;
    loadTab(tab);
  });
});

async function loadTab(tab) {
  try {
    if (tab === "settings") await renderSettingsTab();
    else if (tab === "docker") await renderDockerTab();
    else if (tab === "special-rules") await renderSpecialRulesTab();
    else if (tab === "blocklists") await renderBlocklistsTab();
    else if (tab === "deploy") await renderDeployTab();
    else if (tab === "keys") await renderKeysTab();
    else if (tab === "system-settings") await renderSystemSettingsTab();
    else if (tab === "audit-logs") await renderAuditLogsTab();
  } catch (err) {
    toast("Erreur chargement onglet: " + err.message, "error");
  }
}

/* ---------------------------------------------------------------------- *
 * Tab 1: Interfaces, GeoIP, IPAutor & Zone Rules (firewall.settings)
 * ---------------------------------------------------------------------- */

async function renderSettingsTab() {
  const panel = document.getElementById("tab-settings");
  const [settings, zoneRules, docker] = await Promise.all([
    client.get("/api/firewall/settings"),
    client.get("/api/firewall/zones"),
    client.get("/api/docker/discovery"),
  ]);
  cachedSettings = settings;
  cachedDockerDiscovery = docker;

  const canEdit = me.is_master || me.can_manage_settings;
  const dhcpLines = Object.entries(settings.interface_with_dhcp || {})
    .filter(([, enabled]) => enabled)
    .map(([iface]) => iface)
    .join("\n");

  const filteredZones = zoneFilterState
    ? zoneRules.filter((r) => r.zone === zoneFilterState)
    : zoneRules;

  const containerOptions = (docker.containers || [])
    .map((c) => `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)} (${escapeHtml(c.state)})</option>`)
    .join("");
  const networkOptions = (docker.networks || [])
    .map((n) => `<option value="${escapeHtml(n.name)}">${escapeHtml(n.name)}</option>`)
    .join("");

  panel.innerHTML = `
    <datalist id="dl-containers">${containerOptions}</datalist>
    <datalist id="dl-networks">${networkOptions}</datalist>

    <section class="card">
      <div class="list-header">
        <h2>Interfaces Réseau, IPs de Confiance (IPAutor) &amp; GeoIP (<code>firewall.settings</code>)</h2>
      </div>
      <form id="settings-network-form">
        <div class="grid-2">
          <div class="form-group">
            <label for="cfg-main-inter">Interface Principale Externe (<code>mainInter</code>)</label>
            <input type="text" id="cfg-main-inter" class="input-field font-mono" value="${escapeHtml(settings.main_inter)}" required>
          </div>
          <div class="form-group">
            <label for="cfg-inter-out">Interfaces Sortantes (<code>INTEROut</code> — 1 par ligne: <code>iface;ipv4_cidr;ipv6_cidr</code>)</label>
            <textarea id="cfg-inter-out" class="input-field font-mono" rows="2">${escapeHtml(arrayToLines(settings.inter_out))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-inter-outside">Interfaces Accès Sortant NAT (<code>interfaceToGoOutSide</code>)</label>
            <textarea id="cfg-inter-outside" class="input-field font-mono" rows="3">${escapeHtml(arrayToLines(settings.interface_to_go_outside))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-inter-intern-local">Interfaces Internes ayant accès Local (<code>internInterfaceHaveAccessAsLocal</code>)</label>
            <textarea id="cfg-inter-intern-local" class="input-field font-mono" rows="3">${escapeHtml(arrayToLines(settings.intern_interface_have_access_as_local))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-inter-local">Interfaces Locales (<code>interfaceLocal</code>)</label>
            <textarea id="cfg-inter-local" class="input-field font-mono" rows="2">${escapeHtml(arrayToLines(settings.interface_local))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-inter-dhcp">Interfaces avec DHCP actif (<code>interfaceWithDHCP</code> — clés actives <code>iface;v4;v6</code>)</label>
            <textarea id="cfg-inter-dhcp" class="input-field font-mono" rows="2">${escapeHtml(dhcpLines)}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-inter-norules">Interfaces structure seule sans règles auto (<code>interfaceWithNoRules</code>)</label>
            <textarea id="cfg-inter-norules" class="input-field font-mono" rows="2">${escapeHtml(arrayToLines(settings.interface_with_no_rules))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-ip-autor">IPs de Confiance (<code>IPAutor</code> — IPv4 / IPv6 / CIDR, 1 par ligne)</label>
            <textarea id="cfg-ip-autor" class="input-field font-mono" rows="3">${escapeHtml(arrayToLines(settings.ip_autor))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-ip-autor-dnat-tcp">DNAT TCP IPs de Confiance (<code>IPAutorDnatPortTCP</code> — <code>port,iface,ipv4,ipv6,dest_port</code>)</label>
            <textarea id="cfg-ip-autor-dnat-tcp" class="input-field font-mono" rows="2">${escapeHtml(arrayToLines(settings.ip_autor_dnat_port_tcp))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-ip-autor-dnat-udp">DNAT UDP IPs de Confiance (<code>IPAutorDnatPortUDP</code>)</label>
            <textarea id="cfg-ip-autor-dnat-udp" class="input-field font-mono" rows="2">${escapeHtml(arrayToLines(settings.ip_autor_dnat_port_udp))}</textarea>
          </div>
          <div class="form-group">
            <label for="cfg-country-open">Pays Autorisés Zone Open (<code>countryOpenPort</code>, ex: <code>FR,CH</code>)</label>
            <input type="text" id="cfg-country-open" class="input-field font-mono" value="${escapeHtml(settings.country_open_port)}">
          </div>
          <div class="form-group">
            <label for="cfg-blocked-country">Pays Bloqués 1 &amp; 2 (<code>blockedCountry</code> / <code>blockedCountry2</code>)</label>
            <div style="display:flex;gap:0.5rem;">
              <input type="text" id="cfg-blocked-country" class="input-field font-mono" placeholder="blockedCountry" value="${escapeHtml(settings.blocked_country)}">
              <input type="text" id="cfg-blocked-country-2" class="input-field font-mono" placeholder="blockedCountry2" value="${escapeHtml(settings.blocked_country_2)}">
            </div>
          </div>
        </div>
        ${canEdit ? `<div style="margin-top:1rem;"><button type="submit" class="btn btn-primary">Sauvegarder les Paramètres Réseau &amp; GeoIP</button></div>` : ""}
      </form>
    </section>

    <section class="card" style="margin-top:1.5rem;">
      <div class="list-header">
        <h2>Règles d'Ouverture par Zone (<code>ip_autor</code>, <code>internal</code>, <code>local</code>, <code>open</code>, <code>ww</code>)</h2>
        <div style="display:flex;gap:0.5rem;align-items:center;">
          <select id="zone-filter-select" class="input-field" style="width:auto;">
            <option value="">Toutes les zones (${zoneRules.length})</option>
            <option value="ip_autor" ${zoneFilterState === "ip_autor" ? "selected" : ""}>ip_autor (Trusted IPs)</option>
            <option value="internal" ${zoneFilterState === "internal" ? "selected" : ""}>internal</option>
            <option value="local" ${zoneFilterState === "local" ? "selected" : ""}>local</option>
            <option value="open" ${zoneFilterState === "open" ? "selected" : ""}>open (GeoIP)</option>
            <option value="ww" ${zoneFilterState === "ww" ? "selected" : ""}>ww (WorldWide)</option>
          </select>
          ${canEdit ? `<button type="button" id="btn-new-zone-rule" class="btn btn-primary">+ Nouvelle Règle de Zone</button>` : ""}
        </div>
      </div>
      <p class="text-muted text-sm" style="margin-bottom:1rem;">
        Vous pouvez enregistrer des règles pour n'importe quel conteneur Docker, même arrêté. Lors de la génération de <code>firewall.settings</code>, seules les règles dont le conteneur cible est <strong>RUNNING</strong> seront écrites dans le fichier généré.
      </p>
      <div id="zone-rule-form-slot"></div>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Zone</th>
              <th>Type (Variable)</th>
              <th>Valeur / Cible</th>
              <th>Conteneur Docker</th>
              <th>État Conteneur</th>
              <th>Activé</th>
              <th>Note</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${filteredZones.length ? filteredZones.map((r) => renderZoneRuleRow(r, canEdit)).join("") : `<tr><td colspan="8" class="empty-state">Aucune règle pour ce filtre.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
  `;

  document.getElementById("zone-filter-select").addEventListener("change", (e) => {
    zoneFilterState = e.target.value;
    renderSettingsTab();
  });

  if (canEdit) {
    document.getElementById("settings-network-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const dhcpMap = {};
      for (const line of linesToArray(document.getElementById("cfg-inter-dhcp").value)) {
        dhcpMap[line] = true;
      }
      try {
        await client.put("/api/firewall/settings", {
          main_inter: document.getElementById("cfg-main-inter").value.trim(),
          inter_out: linesToArray(document.getElementById("cfg-inter-out").value),
          interface_to_go_outside: linesToArray(document.getElementById("cfg-inter-outside").value),
          intern_interface_have_access_as_local: linesToArray(document.getElementById("cfg-inter-intern-local").value),
          interface_local: linesToArray(document.getElementById("cfg-inter-local").value),
          interface_with_dhcp: dhcpMap,
          interface_with_no_rules: linesToArray(document.getElementById("cfg-inter-norules").value),
          ip_autor: linesToArray(document.getElementById("cfg-ip-autor").value),
          ip_autor_dnat_port_tcp: linesToArray(document.getElementById("cfg-ip-autor-dnat-tcp").value),
          ip_autor_dnat_port_udp: linesToArray(document.getElementById("cfg-ip-autor-dnat-udp").value),
          country_open_port: document.getElementById("cfg-country-open").value.trim(),
          blocked_country: document.getElementById("cfg-blocked-country").value.trim(),
          blocked_country_2: document.getElementById("cfg-blocked-country-2").value.trim(),
        });
        toast("Paramètres réseau sauvegardés", "success");
        await renderSettingsTab();
      } catch (err) {
        toast("Erreur sauvegarde: " + err.message, "error");
      }
    });

    const newBtn = document.getElementById("btn-new-zone-rule");
    if (newBtn) {
      newBtn.addEventListener("click", () => showZoneRuleForm(null));
    }

    panel.querySelectorAll("[data-edit-zone]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rule = zoneRules.find((r) => r.id === btn.dataset.editZone);
        if (rule) showZoneRuleForm(rule);
      });
    });

    panel.querySelectorAll("[data-delete-zone]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Supprimer cette règle de zone ?")) return;
        try {
          await client.del("/api/firewall/zones/" + btn.dataset.deleteZone);
          toast("Règle supprimée", "success");
          await renderSettingsTab();
        } catch (err) {
          toast("Erreur suppression: " + err.message, "error");
        }
      });
    });
  }
}

function renderZoneRuleRow(r, canEdit) {
  return `<tr>
    <td class="font-mono"><span class="badge">${escapeHtml(r.zone)}</span></td>
    <td class="font-mono">${escapeHtml(r.rule_kind)}</td>
    <td class="font-mono">${escapeHtml(r.value)}</td>
    <td class="font-mono">${escapeHtml(r.container_name || "—")}</td>
    <td>${r.container_name ? statusBadge(r.container_status) : `<span class="text-muted text-sm">Hôte</span>`}</td>
    <td>${r.enabled ? `<span class="badge badge-running">OUI</span>` : `<span class="badge badge-stopped">NON</span>`}</td>
    <td class="text-muted text-sm">${escapeHtml(r.comment || "—")}</td>
    <td>
      ${canEdit ? `
        <button type="button" class="btn btn-secondary btn-sm" data-edit-zone="${escapeHtml(r.id)}">Éditer</button>
        <button type="button" class="btn btn-danger btn-sm" data-delete-zone="${escapeHtml(r.id)}">Suppr.</button>
      ` : "—"}
    </td>
  </tr>`;
}

function showZoneRuleForm(existing) {
  const slot = document.getElementById("zone-rule-form-slot");
  slot.innerHTML = `
    <form id="zone-rule-editor-form" class="card" style="margin-bottom:1rem;background:var(--bg-input);">
      <h3>${existing ? "Modifier la Règle de Zone" : "Nouvelle Règle de Zone"}</h3>
      <div class="grid-2" style="margin-top:0.75rem;">
        <div class="form-group">
          <label for="zr-zone">Zone</label>
          <select id="zr-zone" class="input-field" required>
            ${["ip_autor", "internal", "local", "open", "ww"]
              .map((z) => `<option value="${z}" ${existing && existing.zone === z ? "selected" : ""}>${z}</option>`)
              .join("")}
          </select>
        </div>
        <div class="form-group">
          <label for="zr-kind">Type de Règle</label>
          <select id="zr-kind" class="input-field" required>
            ${[
              "DockerTCP",
              "DockerUDP",
              "OpenPortsTCP",
              "OpenPortsUDP",
              "RedirectPortTCP",
              "RedirectPortUDP",
              "DnatPortTCP",
              "DnatPortUDP",
            ]
              .map((k) => `<option value="${k}" ${existing && existing.rule_kind === k ? "selected" : ""}>${k}</option>`)
              .join("")}
          </select>
        </div>
        <div class="form-group">
          <label for="zr-value">Valeur Brute (ou utilisez l'assistant Docker ci-dessous)</label>
          <input type="text" id="zr-value" class="input-field font-mono" value="${escapeHtml(existing ? existing.value : "")}" placeholder="Ex: 443 ou 443,ext,traefik,443" required>
          <small class="field-hint">Format Docker: <code>port_ext,réseau,conteneur,port_conteneur</code> | Port hôte: <code>80</code> | Redirect: <code>80,8080</code> | DNAT: <code>80,iface,ipv4,ipv6,8080</code></small>
        </div>
        <div class="form-group">
          <label>Assistant rapide règle Docker (remplit automatiquement la valeur)</label>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:0.35rem;">
            <input type="text" id="zr-helper-extport" class="input-field font-mono" placeholder="Port ext (443)">
            <input type="text" id="zr-helper-net" list="dl-networks" class="input-field font-mono" placeholder="Réseau (ext)">
            <input type="text" id="zr-helper-container" list="dl-containers" class="input-field font-mono" placeholder="Conteneur">
            <input type="text" id="zr-helper-cport" class="input-field font-mono" placeholder="Port cible">
          </div>
        </div>
        <div class="form-group">
          <label for="zr-comment">Commentaire (optionnel)</label>
          <input type="text" id="zr-comment" class="input-field" value="${escapeHtml(existing?.comment || "")}">
        </div>
        <div class="form-group" style="display:flex;align-items:center;gap:1rem;padding-top:1.5rem;">
          <label><input type="checkbox" id="zr-enabled" ${!existing || existing.enabled ? "checked" : ""}> Règle activée</label>
          <label for="zr-order">Ordre:</label>
          <input type="number" id="zr-order" class="input-field font-mono" style="width:90px;" value="${existing ? existing.sort_order : 100}">
        </div>
      </div>
      <div style="display:flex;gap:0.5rem;margin-top:0.75rem;">
        <button type="submit" class="btn btn-primary">${existing ? "Mettre à jour" : "Créer"}</button>
        <button type="button" id="zr-cancel" class="btn btn-secondary">Annuler</button>
      </div>
    </form>
  `;

  const updateFromHelper = () => {
    const ep = document.getElementById("zr-helper-extport").value.trim();
    const net = document.getElementById("zr-helper-net").value.trim();
    const c = document.getElementById("zr-helper-container").value.trim();
    const cp = document.getElementById("zr-helper-cport").value.trim();
    if (ep && net && c && cp) {
      document.getElementById("zr-value").value = `${ep},${net},${c},${cp}`;
    }
  };
  ["zr-helper-extport", "zr-helper-net", "zr-helper-container", "zr-helper-cport"].forEach((id) => {
    document.getElementById(id).addEventListener("input", updateFromHelper);
  });

  document.getElementById("zr-cancel").addEventListener("click", () => {
    slot.innerHTML = "";
  });

  document.getElementById("zone-rule-editor-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      zone: document.getElementById("zr-zone").value,
      rule_kind: document.getElementById("zr-kind").value,
      value: document.getElementById("zr-value").value.trim(),
      enabled: document.getElementById("zr-enabled").checked,
      comment: document.getElementById("zr-comment").value.trim() || null,
      sort_order: Number(document.getElementById("zr-order").value) || 0,
    };
    try {
      if (existing) await client.put("/api/firewall/zones/" + existing.id, payload);
      else await client.post("/api/firewall/zones", payload);
      toast("Règle de zone enregistrée", "success");
      await renderSettingsTab();
    } catch (err) {
      toast("Erreur: " + err.message, "error");
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Tab 2: Docker Discovery & Inter-Container Rules (dockerAccessBetweenThem)
 * ---------------------------------------------------------------------- */

async function renderDockerTab() {
  const panel = document.getElementById("tab-docker");
  const [settings, docker, interRules] = await Promise.all([
    client.get("/api/firewall/settings"),
    client.get("/api/docker/discovery"),
    client.get("/api/firewall/docker-rules"),
  ]);
  cachedSettings = settings;
  cachedDockerDiscovery = docker;

  const canEdit = me.is_master || me.can_manage_settings;
  const containerOptions = (docker.containers || [])
    .map((c) => `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)} (${escapeHtml(c.state)})</option>`)
    .join("");
  const networkOptions = (docker.networks || [])
    .map((n) => `<option value="${escapeHtml(n.name)}">${escapeHtml(n.name)}</option>`)
    .join("");

  panel.innerHTML = `
    <datalist id="dl-docker-containers">${containerOptions}</datalist>
    <datalist id="dl-docker-networks">${networkOptions}</datalist>

    <section class="card">
      <div class="list-header">
        <h2>Réseaux Docker &amp; Accès Internet (<code>firewall.settings</code>)</h2>
      </div>
      <form id="docker-networks-settings-form">
        <div class="grid-2">
          <div class="form-group">
            <label for="dk-net-internet">Réseaux Docker avec accès Internet sortant (<code>dockerNetworkWithInternetAccess</code> — 1 par ligne)</label>
            <textarea id="dk-net-internet" class="input-field font-mono" rows="3">${escapeHtml(arrayToLines(settings.docker_network_with_internet_access))}</textarea>
          </div>
          <div class="form-group">
            <label for="dk-net-access">Réseaux Docker gérés par le pare-feu (<code>dockerNetworkWithAccess</code> — 1 par ligne)</label>
            <textarea id="dk-net-access" class="input-field font-mono" rows="3">${escapeHtml(arrayToLines(settings.docker_network_with_access))}</textarea>
          </div>
        </div>
        ${canEdit ? `<button type="submit" class="btn btn-primary" style="margin-top:0.75rem;">Sauvegarder les Réseaux Docker</button>` : ""}
      </form>
    </section>

    <section class="card" style="margin-top:1.5rem;">
      <div class="list-header">
        <h2>Flux Inter-Conteneurs (<code>dockerAccessBetweenThem</code>)</h2>
        ${canEdit ? `<button type="button" id="btn-new-docker-rule" class="btn btn-primary">+ Nouveau Flux Inter-Conteneurs</button>` : ""}
      </div>
      <p class="text-muted text-sm" style="margin-bottom:1rem;">
        Format généré: <code>source;destination;network;proto;ports</code>. Lors du clic sur <strong>Générer</strong>, seules les règles dont les <strong>deux conteneurs (source ET destination) sont RUNNING</strong> sont écrites dans <code>firewall.settings</code>.
      </p>
      <div id="docker-rule-form-slot"></div>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Conteneur Source</th>
              <th>État Source</th>
              <th>Conteneur Destination</th>
              <th>État Destination</th>
              <th>Réseau Docker</th>
              <th>Proto</th>
              <th>Ports</th>
              <th>Activé</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${interRules.length ? interRules.map((r) => `
              <tr>
                <td class="font-mono">${escapeHtml(r.source_container)}</td>
                <td>${statusBadge(r.source_status)}</td>
                <td class="font-mono">${escapeHtml(r.destination_container)}</td>
                <td>${statusBadge(r.destination_status)}</td>
                <td class="font-mono">${escapeHtml(r.network_name)}</td>
                <td class="font-mono">${escapeHtml(r.proto.toUpperCase())}</td>
                <td class="font-mono">${escapeHtml(r.ports)}</td>
                <td>${r.enabled ? `<span class="badge badge-running">OUI</span>` : `<span class="badge badge-stopped">NON</span>`}</td>
                <td>
                  ${canEdit ? `
                    <button type="button" class="btn btn-secondary btn-sm" data-edit-dkrule="${escapeHtml(r.id)}">Éditer</button>
                    <button type="button" class="btn btn-danger btn-sm" data-delete-dkrule="${escapeHtml(r.id)}">Suppr.</button>
                  ` : "—"}
                </td>
              </tr>
            `).join("") : `<tr><td colspan="9" class="empty-state">Aucun flux inter-conteneurs configuré.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card" style="margin-top:1.5rem;">
      <div class="list-header">
        <h2>Inventaire du Démon Docker (<code>${escapeHtml(docker.endpoint)}</code>)</h2>
        <span>${docker.reachable ? `<span class="badge badge-running">CONNECTÉ (${docker.containers.length} conteneurs, ${docker.networks.length} réseaux)</span>` : `<span class="badge badge-missing">INJOIGNABLE: ${escapeHtml(docker.error || "")}</span>`}</span>
      </div>
      <div class="grid-2">
        <div class="table-container">
          <h3>Conteneurs Découverts</h3>
          <table class="data-table">
            <thead><tr><th>Nom</th><th>État</th><th>Image</th><th>Réseaux &amp; IPs</th></tr></thead>
            <tbody>
              ${docker.containers.length ? docker.containers.map((c) => {
                const nets = Object.entries(c.networks || {})
                  .map(([n, ip]) => `${n}: ${ip.ipv4 || "—"} ${ip.ipv6 ? "/ " + ip.ipv6 : ""}`)
                  .join(" | ");
                return `<tr>
                  <td class="font-mono">${escapeHtml(c.name)}</td>
                  <td>${statusBadge(c.state)}</td>
                  <td class="font-mono text-sm">${escapeHtml(c.image)}</td>
                  <td class="font-mono text-sm">${escapeHtml(nets || "—")}</td>
                </tr>`;
              }).join("") : `<tr><td colspan="4" class="empty-state">Aucun conteneur retourné par le démon Docker.</td></tr>`}
            </tbody>
          </table>
        </div>
        <div class="table-container">
          <h3>Réseaux Docker Découverts</h3>
          <table class="data-table">
            <thead><tr><th>Nom</th><th>Driver</th><th>Subnets</th></tr></thead>
            <tbody>
              ${docker.networks.length ? docker.networks.map((n) => `<tr>
                <td class="font-mono">${escapeHtml(n.name)}</td>
                <td class="font-mono">${escapeHtml(n.driver)}</td>
                <td class="font-mono text-sm">${escapeHtml((n.subnets || []).join(", ") || "—")}</td>
              </tr>`).join("") : `<tr><td colspan="3" class="empty-state">Aucun réseau retourné par le démon Docker.</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  `;

  if (canEdit) {
    document.getElementById("docker-networks-settings-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await client.put("/api/firewall/settings", {
          docker_network_with_internet_access: linesToArray(document.getElementById("dk-net-internet").value),
          docker_network_with_access: linesToArray(document.getElementById("dk-net-access").value),
        });
        toast("Réseaux Docker sauvegardés", "success");
        await renderDockerTab();
      } catch (err) {
        toast("Erreur sauvegarde: " + err.message, "error");
      }
    });

    const newBtn = document.getElementById("btn-new-docker-rule");
    if (newBtn) newBtn.addEventListener("click", () => showDockerRuleForm(null));

    panel.querySelectorAll("[data-edit-dkrule]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const rule = interRules.find((r) => r.id === btn.dataset.editDkrule);
        if (rule) showDockerRuleForm(rule);
      });
    });

    panel.querySelectorAll("[data-delete-dkrule]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Supprimer ce flux inter-conteneurs ?")) return;
        try {
          await client.del("/api/firewall/docker-rules/" + btn.dataset.deleteDkrule);
          toast("Flux supprimé", "success");
          await renderDockerTab();
        } catch (err) {
          toast("Erreur suppression: " + err.message, "error");
        }
      });
    });
  }
}

function showDockerRuleForm(existing) {
  const slot = document.getElementById("docker-rule-form-slot");
  slot.innerHTML = `
    <form id="docker-rule-editor-form" class="card" style="margin-bottom:1rem;background:var(--bg-input);">
      <h3>${existing ? "Modifier le Flux Inter-Conteneurs" : "Nouveau Flux Inter-Conteneurs"}</h3>
      <div class="grid-2" style="margin-top:0.75rem;">
        <div class="form-group">
          <label for="dkr-src">Conteneur Source (champ libre ou sélection)</label>
          <input type="text" id="dkr-src" list="dl-docker-containers" class="input-field font-mono" value="${escapeHtml(existing?.source_container || "")}" placeholder="ex: traefik" required>
        </div>
        <div class="form-group">
          <label for="dkr-dst">Conteneur Destination (champ libre ou sélection)</label>
          <input type="text" id="dkr-dst" list="dl-docker-containers" class="input-field font-mono" value="${escapeHtml(existing?.destination_container || "")}" placeholder="ex: jellyfin_theatre" required>
        </div>
        <div class="form-group">
          <label for="dkr-net">Réseau Docker</label>
          <input type="text" id="dkr-net" list="dl-docker-networks" class="input-field font-mono" value="${escapeHtml(existing?.network_name || "")}" placeholder="ex: isolate ou ext" required>
        </div>
        <div class="form-group">
          <label for="dkr-proto">Protocole &amp; Ports (séparés par <code>;</code> si multiples)</label>
          <div style="display:flex;gap:0.5rem;">
            <select id="dkr-proto" class="input-field font-mono" style="width:110px;">
              <option value="tcp" ${!existing || existing.proto === "tcp" ? "selected" : ""}>tcp</option>
              <option value="udp" ${existing?.proto === "udp" ? "selected" : ""}>udp</option>
            </select>
            <input type="text" id="dkr-ports" class="input-field font-mono" value="${escapeHtml(existing?.ports || "")}" placeholder="ex: 8096 ou 80;443" required>
          </div>
        </div>
        <div class="form-group">
          <label for="dkr-comment">Commentaire</label>
          <input type="text" id="dkr-comment" class="input-field" value="${escapeHtml(existing?.comment || "")}">
        </div>
        <div class="form-group" style="display:flex;align-items:center;gap:1rem;padding-top:1.5rem;">
          <label><input type="checkbox" id="dkr-enabled" ${!existing || existing.enabled ? "checked" : ""}> Règle activée</label>
          <label for="dkr-order">Ordre:</label>
          <input type="number" id="dkr-order" class="input-field font-mono" style="width:90px;" value="${existing ? existing.sort_order : 100}">
        </div>
      </div>
      <div style="display:flex;gap:0.5rem;margin-top:0.75rem;">
        <button type="submit" class="btn btn-primary">${existing ? "Mettre à jour" : "Créer"}</button>
        <button type="button" id="dkr-cancel" class="btn btn-secondary">Annuler</button>
      </div>
    </form>
  `;

  document.getElementById("dkr-cancel").addEventListener("click", () => {
    slot.innerHTML = "";
  });

  document.getElementById("docker-rule-editor-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      source_container: document.getElementById("dkr-src").value.trim(),
      destination_container: document.getElementById("dkr-dst").value.trim(),
      network_name: document.getElementById("dkr-net").value.trim(),
      proto: document.getElementById("dkr-proto").value,
      ports: document.getElementById("dkr-ports").value.trim(),
      enabled: document.getElementById("dkr-enabled").checked,
      comment: document.getElementById("dkr-comment").value.trim() || null,
      sort_order: Number(document.getElementById("dkr-order").value) || 0,
    };
    try {
      if (existing) await client.put("/api/firewall/docker-rules/" + existing.id, payload);
      else await client.post("/api/firewall/docker-rules", payload);
      toast("Flux inter-conteneurs enregistré", "success");
      await renderDockerTab();
    } catch (err) {
      toast("Erreur: " + err.message, "error");
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Tab 3: Special Rules Editor & 3-Stage Validator (firewall.rules.special)
 * ---------------------------------------------------------------------- */

async function renderSpecialRulesTab() {
  const panel = document.getElementById("tab-special-rules");
  const data = await client.get("/api/firewall/special-rules");
  const canEdit = me.is_master || me.can_manage_special_rules;

  panel.innerHTML = `
    <section class="card">
      <div class="list-header">
        <h2>Éditeur Structuré <code>firewall.rules.special</code> &amp; Vérificateur d'Intégrité</h2>
        <div style="display:flex;gap:0.5rem;align-items:center;">
          <button type="button" id="btn-validate-special" class="btn btn-secondary">Vérifier l'Intégrité (3 étapes)</button>
          ${canEdit ? `<button type="button" id="btn-save-special" class="btn btn-primary">Sauvegarder .rules.special</button>` : ""}
        </div>
      </div>

      <div class="editor-layout">
        <div>
          <div class="code-editor-wrapper">
            <textarea id="special-rules-textarea" class="code-editor-textarea" spellcheck="false" ${canEdit ? "" : "readonly"}>${escapeHtml(data.script_content)}</textarea>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:0.5rem;">
            <label class="text-sm text-muted">
              <input type="checkbox" id="special-allow-warnings"> Autoriser la sauvegarde malgré les avertissements <code>shellcheck</code> (si <code>bash -n</code> et variables OK)
            </label>
            <span class="text-sm text-muted">Dernière mise à jour : ${escapeHtml(data.updated_at)}</span>
          </div>
          <div id="special-validation-slot">
            ${renderValidationReportHtml(data.validation)}
          </div>
        </div>

        <aside class="card" style="background:var(--bg-main);padding:1rem;">
          <h3>Fonctions <code>firewall.tools</code></h3>
          <p class="text-muted text-sm" style="margin-bottom:0.75rem;">
            Cliquez sur une fonction pour l'insérer dans l'éditeur à la position du curseur.
          </p>
          <div class="tools-ref-list">
            ${(data.tools_functions || []).map((fn, idx) => `
              <div class="tool-fn-card">
                <code>${escapeHtml(fn.usage)}</code>
                <p class="text-muted text-sm">${escapeHtml(fn.description)}</p>
                ${canEdit ? `<button type="button" class="btn btn-secondary btn-sm" style="margin-top:0.4rem;" data-insert-fn="${idx}">Insérer</button>` : ""}
              </div>
            `).join("")}
          </div>
          <details style="margin-top:1rem;">
            <summary class="text-sm" style="cursor:pointer;color:var(--highlight);">Constantes Système Connues (${(data.known_variables || []).length})</summary>
            <div class="font-mono text-sm" style="margin-top:0.5rem;max-height:180px;overflow-y:auto;">
              ${(data.known_variables || []).map((v) => `$${escapeHtml(v)}`).join(", ")}
            </div>
          </details>
        </aside>
      </div>
    </section>
  `;

  const textarea = document.getElementById("special-rules-textarea");
  textarea.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      textarea.value = textarea.value.substring(0, start) + "\t" + textarea.value.substring(end);
      textarea.selectionStart = textarea.selectionEnd = start + 1;
    }
  });

  panel.querySelectorAll("[data-insert-fn]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const fn = data.tools_functions[Number(btn.dataset.insertFn)];
      if (!fn) return;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const snippet = fn.usage + "\n";
      textarea.value = textarea.value.substring(0, start) + snippet + textarea.value.substring(end);
      textarea.focus();
    });
  });

  document.getElementById("btn-validate-special").addEventListener("click", async () => {
    try {
      const report = await client.post("/api/firewall/special-rules/validate", {
        script_content: textarea.value,
        allow_warnings: document.getElementById("special-allow-warnings").checked,
      });
      document.getElementById("special-validation-slot").innerHTML = renderValidationReportHtml(report);
      toast(report.valid ? "Validation 3 étapes réussie" : "Des problèmes ont été détectés", report.valid ? "success" : "error");
    } catch (err) {
      toast("Erreur validation: " + err.message, "error");
    }
  });

  const saveBtn = document.getElementById("btn-save-special");
  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      try {
        const res = await client.put("/api/firewall/special-rules", {
          script_content: textarea.value,
          allow_warnings: document.getElementById("special-allow-warnings").checked,
        });
        document.getElementById("special-validation-slot").innerHTML = renderValidationReportHtml(res.validation);
        toast("firewall.rules.special sauvegardé avec succès", "success");
      } catch (err) {
        if (err.validation) {
          document.getElementById("special-validation-slot").innerHTML = renderValidationReportHtml(err.validation);
        }
        toast("Sauvegarde refusée: " + err.message, "error");
      }
    });
  }
}

function renderValidationReportHtml(v) {
  if (!v) return "";
  const undefList = (v.undefined_variables || [])
    .map((u) => `<li>Ligne ${u.line} : <code>$${escapeHtml(u.variable)}</code> dans <code>${escapeHtml(u.context)}</code></li>`)
    .join("");
  const scList = (v.shellcheck_issues || [])
    .map((i) => `<li><code>${escapeHtml(i)}</code></li>`)
    .join("");

  return `
    <div class="validation-box ${v.valid ? "valid" : "invalid"}">
      <h3>Rapport d'Intégrité en 3 Étapes : ${v.valid ? `<span class="badge badge-running">VALIDE</span>` : `<span class="badge badge-missing">ERREURS DÉTECTÉES</span>`}</h3>
      <ul style="margin-top:0.5rem;padding-left:1.25rem;">
        <li><strong>Étape 1 (Syntaxe <code>bash -n</code>) :</strong> ${v.bash_n_ok ? `<span class="badge badge-running">OK</span>` : `<span class="badge badge-missing">ÉCHEC</span> <pre class="font-mono text-sm">${escapeHtml(v.bash_n_output)}</pre>`}</li>
        <li><strong>Étape 2 (Analyse statique <code>shellcheck</code>) :</strong> ${v.shellcheck_ok ? `<span class="badge badge-running">OK (${(v.shellcheck_issues || []).length} notes)</span>` : `<span class="badge badge-stopped">erreurs shellcheck</span>`}
          ${scList ? `<ul style="margin-top:0.25rem;">${scList}</ul>` : ""}
        </li>
        <li><strong>Étape 3 (Résolution des variables <code>$CHAIN*</code> / <code>$IPS*</code> sur ${v.known_constants_count} constantes connues) :</strong> ${v.variables_ok ? `<span class="badge badge-running">OK (0 variable inconnue)</span>` : `<span class="badge badge-missing">${(v.undefined_variables || []).length} variable(s) non définie(s)</span>`}
          ${undefList ? `<ul style="margin-top:0.25rem;">${undefList}</ul>` : ""}
        </li>
      </ul>
    </div>
  `;
}

/* ---------------------------------------------------------------------- *
 * Tab 4: Blocklists (firewall.get.list)
 * ---------------------------------------------------------------------- */

async function renderBlocklistsTab() {
  const panel = document.getElementById("tab-blocklists");
  const data = await client.get("/api/firewall/blocklists");
  const canEdit = me.is_master || me.can_manage_blocklists;

  panel.innerHTML = `
    <section class="card">
      <div class="list-header">
        <h2>Listes de Blocage IP (<code>firewall.get.list</code>)</h2>
        ${canEdit ? `<button type="button" id="btn-new-blocklist" class="btn btn-primary">+ Ajouter une Liste d'IPs</button>` : ""}
      </div>
      <p class="text-muted text-sm" style="margin-bottom:1rem;">
        Chaque entrée active génère un appel <code>generate_list "&lt;URL&gt;" "&lt;nom&gt;" &amp;</code>. Les flux nécessitant une authentification JSON complexe (comme AbuseIPDB) sont ingérés par <code>simply_ip_sync</code> et exposés en liste brute sans authentification par <code>simply_ip_exporter</code>.
      </p>
      <div id="blocklist-form-slot"></div>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Nom de Liste</th>
              <th>URL du Flux Brut (IPv4/IPv6/CIDR)</th>
              <th>Activé</th>
              <th>Dernier Test HTTP</th>
              <th>Description</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${data.items.length ? data.items.map((b) => `
              <tr>
                <td class="font-mono">${escapeHtml(b.name)}</td>
                <td class="font-mono text-sm">${escapeHtml(b.url)}</td>
                <td>${b.enabled ? `<span class="badge badge-running">OUI</span>` : `<span class="badge badge-stopped">NON</span>`}</td>
                <td>
                  ${b.last_test_ok === true
                    ? `<span class="badge badge-running">OK (${b.last_test_entries || 0} IPs)</span>`
                    : b.last_test_ok === false
                    ? `<span class="badge badge-missing">ÉCHEC</span>`
                    : `<span class="text-muted text-sm">Non testé</span>`}
                </td>
                <td class="text-muted text-sm">${escapeHtml(b.description || "—")}</td>
                <td>
                  ${canEdit ? `
                    <button type="button" class="btn btn-secondary btn-sm" data-test-bl="${escapeHtml(b.id)}">Tester l'URL</button>
                    <button type="button" class="btn btn-secondary btn-sm" data-edit-bl="${escapeHtml(b.id)}">Éditer</button>
                    <button type="button" class="btn btn-danger btn-sm" data-delete-bl="${escapeHtml(b.id)}">Suppr.</button>
                  ` : "—"}
                </td>
              </tr>
            `).join("") : `<tr><td colspan="6" class="empty-state">Aucune blocklist configurée.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card" style="margin-top:1.5rem;">
      <h2>Aperçu du Fichier <code>firewall.get.list</code> Généré</h2>
      <pre class="code-preview">${escapeHtml(data.script_preview)}</pre>
    </section>
  `;

  if (canEdit) {
    const newBtn = document.getElementById("btn-new-blocklist");
    if (newBtn) newBtn.addEventListener("click", () => showBlocklistForm(null));

    panel.querySelectorAll("[data-test-bl]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "Test...";
        try {
          const res = await client.post(`/api/firewall/blocklists/${btn.dataset.testBl}/test`);
          toast(`${res.name}: ${res.message}`, res.valid ? "success" : "error");
          await renderBlocklistsTab();
        } catch (err) {
          toast("Erreur test URL: " + err.message, "error");
          btn.disabled = false;
          btn.textContent = "Tester l'URL";
        }
      });
    });

    panel.querySelectorAll("[data-edit-bl]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = data.items.find((x) => x.id === btn.dataset.editBl);
        if (item) showBlocklistForm(item);
      });
    });

    panel.querySelectorAll("[data-delete-bl]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Supprimer cette liste de blocage ?")) return;
        try {
          await client.del(`/api/firewall/blocklists/${btn.dataset.deleteBl}`);
          toast("Blocklist supprimée", "success");
          await renderBlocklistsTab();
        } catch (err) {
          toast("Erreur suppression: " + err.message, "error");
        }
      });
    });
  }
}

function showBlocklistForm(existing) {
  const slot = document.getElementById("blocklist-form-slot");
  slot.innerHTML = `
    <form id="blocklist-editor-form" class="card" style="margin-bottom:1rem;background:var(--bg-input);">
      <h3>${existing ? "Modifier la Blocklist" : "Nouvelle Blocklist"}</h3>
      <div class="grid-2" style="margin-top:0.75rem;">
        <div class="form-group">
          <label for="bl-name">Nom de Liste (2e argument de <code>generate_list</code>)</label>
          <input type="text" id="bl-name" class="input-field font-mono" value="${escapeHtml(existing?.name || "")}" placeholder="ex: abuseipdb_exporter ou drop_v4" required>
        </div>
        <div class="form-group">
          <label for="bl-url">URL du Flux Brut (HTTP/HTTPS sans auth)</label>
          <input type="url" id="bl-url" class="input-field font-mono" value="${escapeHtml(existing?.url || "")}" placeholder="https://..." required>
        </div>
        <div class="form-group">
          <label for="bl-desc">Description</label>
          <input type="text" id="bl-desc" class="input-field" value="${escapeHtml(existing?.description || "")}">
        </div>
        <div class="form-group" style="display:flex;align-items:center;gap:1rem;padding-top:1.5rem;">
          <label><input type="checkbox" id="bl-enabled" ${!existing || existing.enabled ? "checked" : ""}> Activer dans <code>firewall.get.list</code></label>
          <label for="bl-order">Ordre:</label>
          <input type="number" id="bl-order" class="input-field font-mono" style="width:90px;" value="${existing ? existing.sort_order : 100}">
        </div>
      </div>
      <div style="display:flex;gap:0.5rem;margin-top:0.75rem;">
        <button type="submit" class="btn btn-primary">${existing ? "Mettre à jour" : "Créer"}</button>
        <button type="button" id="bl-cancel" class="btn btn-secondary">Annuler</button>
      </div>
    </form>
  `;

  document.getElementById("bl-cancel").addEventListener("click", () => {
    slot.innerHTML = "";
  });

  document.getElementById("blocklist-editor-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      name: document.getElementById("bl-name").value.trim(),
      url: document.getElementById("bl-url").value.trim(),
      description: document.getElementById("bl-desc").value.trim() || null,
      enabled: document.getElementById("bl-enabled").checked,
      sort_order: Number(document.getElementById("bl-order").value) || 0,
    };
    try {
      if (existing) await client.put(`/api/firewall/blocklists/${existing.id}`, payload);
      else await client.post("/api/firewall/blocklists", payload);
      toast("Blocklist enregistrée", "success");
      await renderBlocklistsTab();
    } catch (err) {
      toast("Erreur: " + err.message, "error");
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Tab 5: Preview, Disk Generation & simply_hook_executor Integration
 * ---------------------------------------------------------------------- */

async function renderDeployTab() {
  const panel = document.getElementById("tab-deploy");
  const [settings, preview] = await Promise.all([
    client.get("/api/firewall/settings"),
    client.get("/api/firewall/preview"),
  ]);
  const canEditSettings = me.is_master || me.can_manage_settings;
  const canDeploy = me.is_master || me.can_deploy_and_reload;

  panel.innerHTML = `
    <section class="card">
      <div class="list-header">
        <h2>Configuration Déploiement, Démon Docker &amp; <code>simply_hook_executor</code></h2>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
          ${canDeploy ? `
            <button type="button" id="btn-deploy-import" class="btn btn-secondary btn-sm">Importer /example</button>
            <button type="button" id="btn-deploy-update-containers" class="btn btn-secondary btn-sm">Hook: Mettre à jour les Conteneurs</button>
          ` : ""}
        </div>
      </div>
      <form id="deploy-config-form">
        <div class="grid-2">
          <div class="form-group">
            <label for="dp-output-dir">Répertoire Cible sur Disque (<code>output_dir</code>)</label>
            <input type="text" id="dp-output-dir" class="input-field font-mono" value="${escapeHtml(settings.output_dir)}" required>
          </div>
          <div class="form-group">
            <label for="dp-docker-endpoint">Endpoint Démon Docker (<code>unix:///var/run/docker.sock</code> ou <code>http://...:2375</code>)</label>
            <input type="text" id="dp-docker-endpoint" class="input-field font-mono" value="${escapeHtml(settings.docker_endpoint)}" required>
          </div>
          <div class="form-group">
            <label for="dp-tools-path">Chemin de référence <code>firewall.tools</code></label>
            <input type="text" id="dp-tools-path" class="input-field font-mono" value="${escapeHtml(settings.tools_script_path)}" required>
          </div>
          <div class="form-group">
            <label for="dp-hook-url">URL de <code>simply_hook_executor</code></label>
            <input type="text" id="dp-hook-url" class="input-field font-mono" value="${escapeHtml(settings.hook_executor_url || "")}" placeholder="http://127.0.0.1:8080">
          </div>
          <div class="form-group">
            <label for="dp-hook-key">API Key <code>simply_hook_executor</code></label>
            <input type="text" id="dp-hook-key" class="input-field font-mono" value="${escapeHtml(settings.hook_executor_api_key || "")}" placeholder="X-API-Key...">
          </div>
          <div class="form-group">
            <label for="dp-hook-secret">Signing Secret <code>simply_hook_executor</code> ${settings.has_hook_signing_secret ? `<span class="badge badge-running">Configuré (chiffré)</span>` : `<span class="badge badge-stopped">Non configuré</span>`}</label>
            <input type="password" id="dp-hook-secret" class="input-field font-mono" placeholder="Laisser vide pour conserver le secret actuel">
          </div>
          <div class="form-group">
            <label for="dp-hook-reload">Nom du Hook de Reload Firewall</label>
            <input type="text" id="dp-hook-reload" class="input-field font-mono" value="${escapeHtml(settings.hook_reload_name)}" required>
          </div>
          <div class="form-group">
            <label for="dp-hook-update">Nom du Hook de Mise à jour Conteneurs</label>
            <input type="text" id="dp-hook-update" class="input-field font-mono" value="${escapeHtml(settings.hook_update_containers_name)}" required>
          </div>
        </div>
        ${canEditSettings ? `<button type="submit" class="btn btn-primary" style="margin-top:0.75rem;">Sauvegarder la Configuration d'Exécution</button>` : ""}
      </form>
    </section>

    <section class="card" style="margin-top:1.5rem;">
      <div class="list-header">
        <h2>Aperçu en Temps Réel des 3 Fichiers Générés</h2>
        <div>
          <span class="badge ${preview.docker_filter_active ? "badge-running" : "badge-unknown"}">
            Filtrage Docker Live: ${preview.docker_filter_active ? "ACTIF" : "DÉMON INJOIGNABLE (toutes règles actives incluses)"}
          </span>
          <span class="badge">Flux Docker: ${preview.active_docker_inter_rules} actifs / ${preview.skipped_docker_inter_rules} omis</span>
          <span class="badge">Zones: ${preview.active_zone_rules} actives / ${preview.skipped_zone_rules} omises</span>
        </div>
      </div>

      <h3 style="margin-top:1rem;">1. <code>${escapeHtml(preview.output_dir)}/firewall.settings</code></h3>
      <pre class="code-preview">${escapeHtml(preview.firewall_settings)}</pre>

      <h3 style="margin-top:1.25rem;">2. <code>${escapeHtml(preview.output_dir)}/firewall.rules.special</code></h3>
      <pre class="code-preview">${escapeHtml(preview.firewall_rules_special)}</pre>

      <h3 style="margin-top:1.25rem;">3. <code>${escapeHtml(preview.output_dir)}/firewall.get.list</code></h3>
      <pre class="code-preview">${escapeHtml(preview.firewall_get.list || preview.firewall_get_list)}</pre>
    </section>
  `;

  if (canEditSettings) {
    document.getElementById("deploy-config-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        output_dir: document.getElementById("dp-output-dir").value.trim(),
        docker_endpoint: document.getElementById("dp-docker-endpoint").value.trim(),
        tools_script_path: document.getElementById("dp-tools-path").value.trim(),
        hook_executor_url: document.getElementById("dp-hook-url").value.trim(),
        hook_executor_api_key: document.getElementById("dp-hook-key").value.trim(),
        hook_reload_name: document.getElementById("dp-hook-reload").value.trim(),
        hook_update_containers_name: document.getElementById("dp-hook-update").value.trim(),
      };
      const secretVal = document.getElementById("dp-hook-secret").value.trim();
      if (secretVal) payload.hook_executor_signing_secret = secretVal;
      try {
        await client.put("/api/firewall/settings", payload);
        toast("Configuration déploiement & Hook Executor sauvegardée", "success");
        await renderDeployTab();
      } catch (err) {
        toast("Erreur sauvegarde: " + err.message, "error");
      }
    });
  }

  if (canDeploy) {
    const impBtn = document.getElementById("btn-deploy-import");
    if (impBtn) {
      impBtn.addEventListener("click", async () => {
        if (!confirm("Ré-importer les fichiers de référence depuis example/MainServ/etc_firewall ?")) return;
        try {
          const summary = await client.post("/api/firewall/import", {});
          toast(
            `Import terminé: ${summary.zone_rules_imported} zones, ${summary.docker_inter_rules_imported} flux Docker, ${summary.blocklists_imported} blocklists`,
            "success"
          );
          await renderDeployTab();
        } catch (err) {
          toast("Erreur import: " + err.message, "error");
        }
      });
    }

    const updBtn = document.getElementById("btn-deploy-update-containers");
    if (updBtn) {
      updBtn.addEventListener("click", async () => {
        try {
          const res = await client.post("/api/firewall/update-containers");
          toast(`Hook '${res.hook_name}' exécuté (HTTP ${res.status_code})`, "success");
        } catch (err) {
          toast("Erreur hook mise à jour conteneurs: " + err.message, "error");
        }
      });
    }
  }
}

/* ---------------------------------------------------------------------- *
 * Tab 6: API Keys & Permissions
 * ---------------------------------------------------------------------- */

async function renderKeysTab() {
  const panel = document.getElementById("tab-keys");
  const keys = await client.get("/api/keys");
  const canManage = me.is_master || me.can_manage_keys;

  panel.innerHTML = `
    <section class="card">
      <div class="list-header">
        <h2>API Keys &amp; Permissions</h2>
        ${canManage ? `<button type="button" class="btn btn-primary" id="new-key-btn">+ New Key</button>` : ""}
      </div>
      <div id="key-credentials-banner"></div>
      <div id="key-form-slot"></div>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Prefix</th>
              <th>Tier</th>
              <th>Global Rights</th>
              <th>Bound IPs</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${keys.length ? keys.map((k) => renderKeyRow(k, canManage)).join("") : `<tr><td colspan="6" class="empty-state">No keys visible.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
  `;

  if (canManage) {
    const newBtn = document.getElementById("new-key-btn");
    if (newBtn) newBtn.addEventListener("click", () => showKeyForm(null));

    panel.querySelectorAll("[data-edit-key]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = keys.find((k) => k.id === btn.dataset.editKey);
        if (target) showKeyForm(target);
      });
    });

    panel.querySelectorAll("[data-rotate-key]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Rotate this API key? The previous key will stop working immediately.")) return;
        try {
          const res = await client.post(`/api/keys/${btn.dataset.rotateKey}/rotate`);
          showIssuedSecretBanner("Rotated API Key", res.api_key, null);
          await renderKeysTab();
        } catch (err) {
          toast("Rotate failed: " + err.message, "error");
        }
      });
    });

    panel.querySelectorAll("[data-rotate-secret]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Rotate this key's HMAC signing secret?")) return;
        try {
          const res = await client.post(`/api/keys/${btn.dataset.rotateSecret}/rotate-secret`);
          showIssuedSecretBanner("Rotated Signing Secret", null, res.signing_secret);
        } catch (err) {
          toast("Rotate secret failed: " + err.message, "error");
        }
      });
    });

    panel.querySelectorAll("[data-delete-key]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Revoke and delete this API key?")) return;
        try {
          await client.del(`/api/keys/${btn.dataset.deleteKey}`);
          toast("API key deleted", "success");
          await renderKeysTab();
        } catch (err) {
          toast("Delete failed: " + err.message, "error");
        }
      });
    });
  }
}

function keyScopes(k) {
  if (k.is_master) return '<span class="badge badge-tier badge-master">master</span>';
  const chips = [];
  if (k.can_manage_keys) chips.push('<span class="badge badge-scope">keys</span>');
  if (k.can_manage_settings) chips.push('<span class="badge badge-scope">settings/zones/docker</span>');
  if (k.can_manage_special_rules) chips.push('<span class="badge badge-scope">special-rules</span>');
  if (k.can_manage_blocklists) chips.push('<span class="badge badge-scope">blocklists</span>');
  if (k.can_deploy_and_reload) chips.push('<span class="badge badge-scope">deploy/reload</span>');
  return chips.length ? chips.join(" ") : '<span class="text-muted text-sm">read-only</span>';
}

function renderKeyRow(k, canManage) {
  const tier = describeTier(k);
  return `<tr>
    <td><strong>${escapeHtml(k.name)}</strong></td>
    <td class="font-mono text-muted text-sm">${escapeHtml(k.prefix)}…</td>
    <td><span class="badge badge-tier ${tier.tier === 'master' ? 'badge-master' : 'badge-daughter'}">${escapeHtml(tier.label)}</span></td>
    <td>${keyScopes(k)}</td>
    <td class="font-mono text-sm">${escapeHtml(k.bound_ips || "any")}</td>
    <td>
      ${canManage ? `
        <button type="button" class="btn btn-secondary btn-sm" data-edit-key="${escapeHtml(k.id)}">Edit</button>
        ${!k.is_master ? `
          <button type="button" class="btn btn-secondary btn-sm" data-rotate-key="${escapeHtml(k.id)}">Rotate Key</button>
          <button type="button" class="btn btn-secondary btn-sm" data-rotate-secret="${escapeHtml(k.id)}">Rotate Secret</button>
          <button type="button" class="btn btn-danger btn-sm" data-delete-key="${escapeHtml(k.id)}">Delete</button>
        ` : ""}
      ` : "—"}
    </td>
  </tr>`;
}

function showIssuedSecretBanner(title, apiKey, signingSecret) {
  const banner = document.getElementById("key-credentials-banner");
  if (!banner) return;
  banner.innerHTML = `
    <div class="card" style="margin-bottom:1rem;border-color:var(--accent);">
      <h3>${escapeHtml(title)} (Copy now — shown only once)</h3>
      ${apiKey ? `<p class="font-mono text-sm" style="margin-top:0.5rem;"><strong>API Key:</strong> <code>${escapeHtml(apiKey)}</code></p>` : ""}
      ${signingSecret ? `<p class="font-mono text-sm" style="margin-top:0.35rem;"><strong>Signing Secret:</strong> <code>${escapeHtml(signingSecret)}</code></p>` : ""}
    </div>
  `;
}

function showKeyForm(existing) {
  const slot = document.getElementById("key-form-slot");
  const isMasterTarget = existing && existing.is_master;
  slot.innerHTML = `
    <form id="key-editor-form" class="card" style="margin-bottom:1rem;background:var(--bg-input);">
      <h3>${existing ? `Edit Key: ${escapeHtml(existing.name)}` : "Create New Sub-Key"}</h3>
      <div class="grid-2" style="margin-top:0.75rem;">
        <div class="form-group">
          <label for="kf-name">Key Name</label>
          <input type="text" id="kf-name" class="input-field" value="${escapeHtml(existing?.name || "")}" ${isMasterTarget ? "disabled" : "required"}>
        </div>
        <div class="form-group">
          <label for="kf-bound-ips">Bound IPs / CIDRs (comma-separated, optional)</label>
          <input type="text" id="kf-bound-ips" class="input-field font-mono" value="${escapeHtml(existing?.bound_ips || "")}" placeholder="10.0.0.0/8, 192.168.1.10">
        </div>
      </div>
      ${!isMasterTarget ? `
        <div style="display:flex;gap:1.25rem;flex-wrap:wrap;margin-top:0.75rem;">
          <label><input type="checkbox" id="kf-manage-keys" ${existing?.can_manage_keys ? "checked" : ""}> <code>can_manage_keys</code></label>
          <label><input type="checkbox" id="kf-manage-settings" ${existing?.can_manage_settings ? "checked" : ""}> <code>can_manage_settings</code></label>
          <label><input type="checkbox" id="kf-manage-special" ${existing?.can_manage_special_rules ? "checked" : ""}> <code>can_manage_special_rules</code></label>
          <label><input type="checkbox" id="kf-manage-blocklists" ${existing?.can_manage_blocklists ? "checked" : ""}> <code>can_manage_blocklists</code></label>
          <label><input type="checkbox" id="kf-deploy" ${existing?.can_deploy_and_reload ? "checked" : ""}> <code>can_deploy_and_reload</code></label>
        </div>
      ` : `<p class="text-muted text-sm" style="margin-top:0.5rem;">Master key permissions are immutable; only <code>bound_ips</code> may be updated.</p>`}
      <div style="display:flex;gap:0.5rem;margin-top:0.75rem;">
        <button type="submit" class="btn btn-primary">${existing ? "Save Changes" : "Create Key"}</button>
        <button type="button" id="kf-cancel" class="btn btn-secondary">Cancel</button>
      </div>
    </form>
  `;

  document.getElementById("kf-cancel").addEventListener("click", () => {
    slot.innerHTML = "";
  });

  document.getElementById("key-editor-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      if (existing) {
        const payload = {
          bound_ips: document.getElementById("kf-bound-ips").value.trim(),
        };
        if (!isMasterTarget) {
          payload.name = document.getElementById("kf-name").value.trim();
          payload.can_manage_keys = document.getElementById("kf-manage-keys").checked;
          payload.can_manage_settings = document.getElementById("kf-manage-settings").checked;
          payload.can_manage_special_rules = document.getElementById("kf-manage-special").checked;
          payload.can_manage_blocklists = document.getElementById("kf-manage-blocklists").checked;
          payload.can_deploy_and_reload = document.getElementById("kf-deploy").checked;
        }
        await client.put(`/api/keys/${existing.id}`, payload);
        toast("API key updated", "success");
        await renderKeysTab();
      } else {
        const res = await client.post("/api/keys", {
          name: document.getElementById("kf-name").value.trim(),
          bound_ips: document.getElementById("kf-bound-ips").value.trim() || null,
          can_manage_keys: document.getElementById("kf-manage-keys").checked,
          can_manage_settings: document.getElementById("kf-manage-settings").checked,
          can_manage_special_rules: document.getElementById("kf-manage-special").checked,
          can_manage_blocklists: document.getElementById("kf-manage-blocklists").checked,
          can_deploy_and_reload: document.getElementById("kf-deploy").checked,
        });
        await renderKeysTab();
        showIssuedSecretBanner(`Created Key '${res.key.name}'`, res.api_key, res.signing_secret);
      }
    } catch (err) {
      toast("Save key failed: " + err.message, "error");
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Tab: System Settings (Master only)
 * ---------------------------------------------------------------------- */

async function renderSystemSettingsTab() {
  const panel = document.getElementById("tab-system-settings");
  if (!me.is_master) {
    panel.innerHTML = '<section class="card"><p class="empty-state">System settings are visible to the Master key only.</p></section>';
    return;
  }
  const s = await client.get("/api/system/settings");
  const item = (label, value) => `
    <div class="kv-item">
      <span class="kv-key">${escapeHtml(label)}</span>
      <span class="kv-value">${value}</span>
    </div>
  `;
  const trustedProxiesDisplay = (s.trusted_proxies && s.trusted_proxies.length > 0)
    ? `<div class="tag-list">${s.trusted_proxies.map((p) => `<span class="badge badge-scope font-mono">${escapeHtml(p)}</span>`).join(' ')}</div>`
    : '<span class="text-muted">None configured</span>';

  panel.innerHTML = `
    <section class="card">
      <div class="list-header">
        <h2>System Configuration</h2>
      </div>
      <p class="subtitle mb-4">Effective runtime settings and daemon counters. Visible to Master keys only.</p>
      <div class="kv-grid">
        ${[
          item("Trusted Proxies", trustedProxiesDisplay),
          item("Secrets at rest", s.encryption_enabled
            ? '<span class="badge badge-success">encrypted</span>'
            : '<span class="badge badge-timeout">unencrypted</span>'),
          item("Firewall Output Dir", `<span class="font-mono">${escapeHtml(s.output_dir)}</span>`),
          item("Hook Executor URL", s.hook_executor_url ? `<span class="font-mono">${escapeHtml(s.hook_executor_url)}</span>` : '<span class="text-muted">Not configured</span>'),
          item("Zone Rules", s.zone_rules_count),
          item("Docker Inter-Rules", s.docker_rules_count),
          item("Blocklists", s.blocklists_count),
          item("Special Rules", s.special_rules_count),
          item("API Keys", s.api_key_count),
          item("Audit Logs stored", s.audit_log_count),
        ].join("")}
      </div>
    </section>
  `;
}

/* ---------------------------------------------------------------------- *
 * Tab: Standardized Audit Logs
 * ---------------------------------------------------------------------- */

let auditFilterState = { action: "", client_ip: "", api_key: "", since: "", until: "", page: 1, limit: 50 };

async function renderAuditLogsTab() {
  const panel = document.getElementById("tab-audit-logs");
  if (!me.is_master) {
    panel.innerHTML = '<section class="card"><p class="empty-state">Audit logs are visible to the Master key only.</p></section>';
    return;
  }
  const offset = (auditFilterState.page - 1) * auditFilterState.limit;
  const params = new URLSearchParams({
    limit: String(auditFilterState.limit),
    offset: String(offset),
  });
  if (auditFilterState.action) params.set("action", auditFilterState.action);
  if (auditFilterState.client_ip) params.set("client_ip", auditFilterState.client_ip);
  if (auditFilterState.api_key) params.set("api_key", auditFilterState.api_key);
  if (auditFilterState.since) {
    const d = new Date(auditFilterState.since);
    if (!Number.isNaN(d.getTime())) params.set("since", d.toISOString());
  }
  if (auditFilterState.until) {
    const d = new Date(auditFilterState.until);
    if (!Number.isNaN(d.getTime())) params.set("until", d.toISOString());
  }
  const qs = params.toString();
  const logs = await client.get("/api/audit-logs" + (qs ? "?" + qs : ""));

  panel.innerHTML = `
    <section class="card">
      <div class="list-header">
        <h2>Audit Logs</h2>
      </div>
      <p class="subtitle mb-4">Recent mutating firewall actions across the system. Master keys only.</p>
      <div class="filters mb-4" style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
        <input type="text" id="audit-action-filter" class="input-field font-mono" list="audit-action-options" placeholder="Filter by action..." value="${escapeHtml(auditFilterState.action)}">
        <datalist id="audit-action-options">
          <option value="KEY_CREATE"></option>
          <option value="KEY_UPDATE"></option>
          <option value="KEY_DELETE"></option>
          <option value="KEY_ROTATE"></option>
          <option value="KEY_SECRET_ROTATE"></option>
          <option value="ZONE_RULE_CREATE"></option>
          <option value="ZONE_RULE_UPDATE"></option>
          <option value="ZONE_RULE_DELETE"></option>
          <option value="DOCKER_RULE_CREATE"></option>
          <option value="DOCKER_RULE_UPDATE"></option>
          <option value="DOCKER_RULE_DELETE"></option>
          <option value="SPECIAL_RULE_CREATE"></option>
          <option value="SPECIAL_RULE_UPDATE"></option>
          <option value="SPECIAL_RULE_DELETE"></option>
          <option value="BLOCKLIST_CREATE"></option>
          <option value="BLOCKLIST_UPDATE"></option>
          <option value="BLOCKLIST_DELETE"></option>
          <option value="FILES_GENERATE"></option>
          <option value="FIREWALL_RELOAD"></option>
        </datalist>
        <input type="text" id="audit-ip-filter" class="input-field font-mono" placeholder="Filter by client IP..." value="${escapeHtml(auditFilterState.client_ip)}">
        <input type="text" id="audit-key-filter" class="input-field" placeholder="Filter by API key..." value="${escapeHtml(auditFilterState.api_key)}">
        <input type="datetime-local" id="audit-since-filter" class="input-field" title="Since (inclusive)" value="${escapeHtml(auditFilterState.since)}">
        <input type="datetime-local" id="audit-until-filter" class="input-field" title="Until (exclusive)" value="${escapeHtml(auditFilterState.until)}">
        <button type="button" id="audit-search-btn" class="btn btn-icon" title="Search">🔍</button>
        <button type="button" id="audit-clear-btn" class="btn btn-secondary btn-sm">Clear</button>
      </div>
      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>API Key</th>
              <th>Client IP</th>
              <th>Action</th>
              <th>Target</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${logs.length ? logs.map(auditRow).join("") : `<tr><td colspan="6" class="empty-state">No audit entries matching filter.</td></tr>`}
          </tbody>
        </table>
      </div>
      <div class="pagination" style="display:flex;gap:0.75rem;align-items:center;margin-top:1rem;justify-content:flex-end;">
        <button id="audit-btn-prev" class="btn btn-icon" ${auditFilterState.page <= 1 ? "disabled" : ""}>&laquo; Prev</button>
        <span id="audit-page-indicator">Page ${auditFilterState.page}</span>
        <button id="audit-btn-next" class="btn btn-icon" ${logs.length < auditFilterState.limit ? "disabled" : ""}>Next &raquo;</button>
      </div>
    </section>
  `;

  document.getElementById("audit-search-btn").addEventListener("click", async () => {
    auditFilterState.action = document.getElementById("audit-action-filter").value.trim();
    auditFilterState.client_ip = document.getElementById("audit-ip-filter").value.trim();
    auditFilterState.api_key = document.getElementById("audit-key-filter").value.trim();
    auditFilterState.since = document.getElementById("audit-since-filter").value;
    auditFilterState.until = document.getElementById("audit-until-filter").value;
    auditFilterState.page = 1;
    await renderAuditLogsTab();
  });

  document.getElementById("audit-clear-btn").addEventListener("click", async () => {
    auditFilterState = { action: "", client_ip: "", api_key: "", since: "", until: "", page: 1, limit: 50 };
    await renderAuditLogsTab();
  });

  ['audit-action-filter', 'audit-ip-filter', 'audit-key-filter'].forEach((id) => {
    document.getElementById(id)?.addEventListener("keydown", async (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        document.getElementById("audit-search-btn").click();
      }
    });
  });

  document.getElementById("audit-btn-prev").addEventListener("click", async () => {
    if (auditFilterState.page > 1) {
      auditFilterState.page--;
      await renderAuditLogsTab();
    }
  });

  document.getElementById("audit-btn-next").addEventListener("click", async () => {
    if (logs.length >= auditFilterState.limit) {
      auditFilterState.page++;
      await renderAuditLogsTab();
    }
  });
}

function auditRow(a) {
  const dateStr = a.timestamp ? new Date(a.timestamp).toLocaleString() : "—";
  return `<tr>
    <td class="font-mono text-sm">${escapeHtml(dateStr)}</td>
    <td>${escapeHtml(a.api_key_name || "")} <span class="font-mono text-muted text-sm">(${escapeHtml(a.api_key_prefix || "")})</span></td>
    <td class="font-mono text-sm">${escapeHtml(a.client_ip || "")}</td>
    <td><span class="badge badge-scope">${escapeHtml(a.action)}</span></td>
    <td class="text-sm">${escapeHtml(a.target_resource || "—")}</td>
    <td class="text-muted text-sm">${escapeHtml(a.details || "—")}</td>
  </tr>`;
}

/* ---------------------------------------------------------------------- *
 * Auto-restore session on reload
 * ---------------------------------------------------------------------- */

(async function autoRestoreSession() {
  const saved = loadSessionCredentials();
  if (!saved) return;
  try {
    await attemptSignIn(saved.apiKey, saved.signingSecret);
  } catch {
    clearSessionCredentials();
  }
})();
