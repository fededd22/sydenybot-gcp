import "dotenv/config";
import express from "express";
import http from "http";
import path from "path";
import fs from "fs";
import os from "os";
import crypto from "crypto";
import { spawn, execSync, ChildProcess } from "child_process";
import httpProxy from "http-proxy";
import QRCode from "qrcode";

// =============================================================================
// V2Ray VLESS/VMess/Trojan server -- Telegram-bot-only admin panel
// -----------------------------------------------------------------------------
// The former React/Vite web dashboard (with username/password login) has been
// completely removed. The ONLY way to administer this server now is through
// the Telegram bot below, and the bot only responds to a single hard-coded
// admin chat id (TELEGRAM_ADMIN_CHAT_ID). Everyone else is ignored.
// The Express server that remains is just a minimal HTTP endpoint required by
// hosting platforms (Cloud Run, Docker HEALTHCHECK, etc.) plus the actual
// WebSocket proxy that forwards VPN traffic to the V2Ray core -- neither of
// those is an "admin interface".
// =============================================================================

// Global process exception safety handlers to prevent network EPIPE / ECONNRESET from crashing Node.js
process.on("uncaughtException", (err) => {
  console.error("[Uncaught Exception] Error:", err?.message || err);
  if (err && (err as any).stack) {
    console.error((err as any).stack);
  }
});

process.on("unhandledRejection", (reason) => {
  console.error("[Unhandled Rejection] Reason:", reason);
});

const PORT = Number(process.env.PORT) || 3000;
const V2RAY_PORT = 10080;

const app = express();
const server = http.createServer(app);

app.use(express.json());

// -----------------------------------------------------------------------------
// Auto-detected public host (Cloud Run domain, e.g. feed5-881375239149.europe-west1.run.app)
// -----------------------------------------------------------------------------
// Cloud Run does NOT expose its own public URL as an env var, so previously the
// only way to fill in the config links was to hard-code APP_URL by hand after
// every deploy. This section auto-detects the domain in two complementary ways:
//   1) Passively: any incoming HTTP request to this server (Cloud Run's front-end
//      always forwards the real public Host to the container) is inspected and,
//      if it looks like a real public domain, cached and persisted to disk.
//   2) Actively: on startup, if we're running on Cloud Run (K_SERVICE is set),
//      we ask the internal metadata server for the project number + region and
//      construct the modern Cloud Run domain form: SERVICE-PROJECTNUMBER.REGION.run.app
// APP_URL, if set explicitly, always takes priority over both of these.
const detectedHostFilePath = path.join(process.cwd(), "detected-host.json");
let cachedPublicHost: string | null = null;

function isLikelyPublicHost(h: string): boolean {
  if (!h) return false;
  const host = h.split(":")[0].toLowerCase();
  if (host === "localhost" || host === "0.0.0.0") return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false; // plain IP
  if (!host.includes(".")) return false;
  return true;
}

function rememberPublicHost(host: string) {
  if (!isLikelyPublicHost(host) || host === cachedPublicHost) return;
  cachedPublicHost = host;
  try {
    fs.writeFileSync(detectedHostFilePath, JSON.stringify({ host, updatedAt: new Date().toISOString() }, null, 2), "utf8");
  } catch {
    /* best-effort only */
  }
  addLog(`Auto-detected public domain: ${host}`);
}

function loadPersistedHost() {
  try {
    if (fs.existsSync(detectedHostFilePath)) {
      const data = JSON.parse(fs.readFileSync(detectedHostFilePath, "utf8"));
      if (data?.host && isLikelyPublicHost(data.host)) {
        cachedPublicHost = data.host;
      }
    }
  } catch {
    /* ignore */
  }
}
loadPersistedHost();

// Passive detection: inspect the Host header of every incoming request.
app.use((req, _res, next) => {
  const forwarded = (req.headers["x-forwarded-host"] as string) || req.headers.host;
  if (forwarded) rememberPublicHost(forwarded.split(",")[0].trim());
  next();
});

// Active detection: ask the GCP metadata server (only reachable/valid on Cloud Run).
async function detectCloudRunHostFromMetadata(): Promise<string | null> {
  const service = process.env.K_SERVICE;
  if (!service) return null; // not running on Cloud Run

  try {
    const metaHeaders = { "Metadata-Flavor": "Google" };
    const [regionRes, projectRes] = await Promise.all([
      fetch("http://metadata.google.internal/computeMetadata/v1/instance/region", { headers: metaHeaders }),
      fetch("http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id", { headers: metaHeaders })
    ]);
    if (!regionRes.ok || !projectRes.ok) return null;

    const regionRaw = (await regionRes.text()).trim(); // e.g. "projects/123456789/regions/europe-west1"
    const projectNumber = (await projectRes.text()).trim();
    const region = regionRaw.split("/").pop();
    if (!region || !projectNumber) return null;

    // Modern Cloud Run default-domain format.
    return `${service}-${projectNumber}.${region}.run.app`;
  } catch (e: any) {
    addLog(`Metadata-server domain auto-detection failed (will fall back to request-based detection): ${e?.message || e}`);
    return null;
  }
}

// Try active detection once at startup, without blocking server boot.
detectCloudRunHostFromMetadata().then((detected) => {
  if (detected && !cachedPublicHost) rememberPublicHost(detected);
});

// -----------------------------------------------------------------------------
// Logging
// -----------------------------------------------------------------------------
const logs: string[] = [];
function addLog(message: string) {
  const timestamp = new Date().toISOString();
  const formattedLog = `[${timestamp}] ${message}`;
  logs.push(formattedLog);
  if (logs.length > 500) {
    logs.shift();
  }
  console.log(formattedLog);
}

// -----------------------------------------------------------------------------
// V2Ray process state (zero-downtime A/B slot hot-swap, unchanged from before)
// -----------------------------------------------------------------------------
let v2rayProcessA: ChildProcess | null = null;
let v2rayProcessB: ChildProcess | null = null;
let activeSlot: "A" | "B" = "A";
let isStartingSlot = { A: false, B: false };

function getSlotPorts(slot: string) {
  if (slot === "B") {
    return { vless: 10090, vmess: 10091, trojan: 10092 };
  }
  return { vless: 10080, vmess: 10081, trojan: 10082 };
}

// -----------------------------------------------------------------------------
// Clients database (clients.json) -- no more "admin" credentials block, since
// there is no login anymore. Just the list of VPN client configs.
// -----------------------------------------------------------------------------
const clientsFilePath = path.join(process.cwd(), "clients.json");

function initClientsDB() {
  if (!fs.existsSync(clientsFilePath)) {
    const defaultDB = {
      clients: [
        {
          id: "default",
          name: "Default Client",
          protocol: "vless",
          uuid: "d2cb8181-233c-4d18-9972-8a1b04db0044",
          path: "/by_moon",
          limitGB: 0, // 0 means unlimited
          consumedUpload: 0,
          consumedDownload: 0,
          duration: "unlimited",
          durationValue: 0,
          createdAt: new Date().toISOString(),
          expiresAt: null,
          enabled: true
        }
      ]
    };
    fs.writeFileSync(clientsFilePath, JSON.stringify(defaultDB, null, 2), "utf8");
    addLog("Created initial clients.json database.");
  }
}

function getPersistedClients(): any[] {
  if (fs.existsSync(clientsFilePath)) {
    try {
      const data = JSON.parse(fs.readFileSync(clientsFilePath, "utf8"));
      return data.clients || [];
    } catch (e) {
      return [];
    }
  }
  return [];
}

function savePersistedClients(clients: any[]) {
  let db: any = { clients };
  try {
    if (fs.existsSync(clientsFilePath)) {
      const existing = JSON.parse(fs.readFileSync(clientsFilePath, "utf8"));
      db = { ...existing, clients };
    }
  } catch (e) {
    // fall back to a clean db object
  }
  fs.writeFileSync(clientsFilePath, JSON.stringify(db, null, 2), "utf8");
}

// -----------------------------------------------------------------------------
// V2Ray binary bootstrap (auto-download, unchanged)
// -----------------------------------------------------------------------------
const binDir = path.join(process.cwd(), "bin");
const v2rayPath = path.join(binDir, "v2ray");

function ensureV2RayBinary() {
  if (fs.existsSync(v2rayPath)) {
    addLog("V2Ray binary already exists at " + v2rayPath);
    return;
  }

  addLog("V2Ray binary not found. Preparing to download...");
  try {
    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }

    const zipPath = path.join(binDir, "v2ray-linux-64.zip");
    addLog("Downloading V2Ray core zip from GitHub releases...");

    execSync(`curl -L -o "${zipPath}" "https://github.com/v2fly/v2ray-core/releases/download/v5.14.1/v2ray-linux-64.zip"`, {
      stdio: "inherit"
    });

    addLog("Extracting V2Ray core zip...");
    execSync(`unzip -o "${zipPath}" -d "${binDir}"`, {
      stdio: "inherit"
    });

    addLog("Setting executable permission on v2ray...");
    execSync(`chmod +x "${v2rayPath}"`, {
      stdio: "inherit"
    });

    if (fs.existsSync(zipPath)) {
      fs.unlinkSync(zipPath);
    }

    addLog("V2Ray binary successfully installed.");
  } catch (error: any) {
    addLog(`ERROR installing V2Ray binary: ${error?.message || error}`);
  }
}

function getV2RayConfig() {
  const configPath = path.join(process.cwd(), "config.json");
  try {
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, "utf8"));
    }
  } catch (err: any) {
    addLog(`Error reading config.json: ${err.message}`);
  }
  return null;
}

function getV2RayPath(): string {
  const config = getV2RayConfig();
  const pathVal = config?.inbounds?.[0]?.streamSettings?.wsSettings?.path;
  return pathVal || "/by_moon";
}

// Synchronize V2Ray configuration with current active clients (unchanged)
function syncV2RayConfig(slot: "A" | "B" = "A") {
  const clients = getPersistedClients();
  const configPath = path.join(process.cwd(), `config_${slot}.json`);

  try {
    let currentConfig = getV2RayConfig();
    if (!currentConfig) {
      addLog("Failed to read config template for sync.");
      return;
    }

    const activeClients = clients.filter((c: any) => {
      if (!c.enabled) return false;
      if (c.expiresAt && new Date(c.expiresAt) < new Date()) return false;

      const totalConsumed = (c.consumedUpload || 0) + (c.consumedDownload || 0);
      const limitBytes = (c.limitGB || 0) * 1024 * 1024 * 1024;
      if (c.limitGB > 0 && totalConsumed >= limitBytes) return false;

      return true;
    });

    if (currentConfig.inbounds) {
      let vlessInbound = currentConfig.inbounds.find((i: any) => i.protocol === "vless");
      let vmessInbound = currentConfig.inbounds.find((i: any) => i.protocol === "vmess");
      let trojanInbound = currentConfig.inbounds.find((i: any) => i.protocol === "trojan");

      const vlessPath = vlessInbound?.streamSettings?.wsSettings?.path || "/by_moon";

      const activeVlessClients = activeClients.filter((c: any) => !c.protocol || c.protocol === "vless");
      const activeVmessClients = activeClients.filter((c: any) => c.protocol === "vmess");
      const activeTrojanClients = activeClients.filter((c: any) => c.protocol === "trojan");

      const ports = getSlotPorts(slot);

      if (!vlessInbound) {
        vlessInbound = {
          listen: "0.0.0.0",
          port: ports.vless,
          protocol: "vless",
          settings: { clients: [], decryption: "none" },
          streamSettings: {
            network: "ws",
            wsSettings: { path: vlessPath },
            sockopt: { tcpFastOpen: true, tcpKeepAliveInterval: 15 }
          }
        };
        currentConfig.inbounds.push(vlessInbound);
      } else {
        vlessInbound.port = ports.vless;
      }

      if (!vmessInbound) {
        vmessInbound = {
          listen: "0.0.0.0",
          port: ports.vmess,
          protocol: "vmess",
          settings: { clients: [] },
          streamSettings: {
            network: "ws",
            wsSettings: { path: vlessPath },
            sockopt: { tcpFastOpen: true, tcpKeepAliveInterval: 15 }
          }
        };
        currentConfig.inbounds.push(vmessInbound);
      } else {
        vmessInbound.port = ports.vmess;
      }

      if (!trojanInbound) {
        trojanInbound = {
          listen: "0.0.0.0",
          port: ports.trojan,
          protocol: "trojan",
          settings: { clients: [] },
          streamSettings: {
            network: "ws",
            wsSettings: { path: vlessPath },
            sockopt: { tcpFastOpen: true, tcpKeepAliveInterval: 15 }
          }
        };
        currentConfig.inbounds.push(trojanInbound);
      } else {
        trojanInbound.port = ports.trojan;
      }

      vlessInbound.settings.clients = activeVlessClients.map((c: any) => ({ id: c.uuid, level: 0 }));
      if (vlessInbound.settings.clients.length === 0) {
        vlessInbound.settings.clients.push({ id: "d2cb8181-233c-4d18-9972-8a1b04db0044", level: 0 });
      }

      vmessInbound.settings.clients = activeVmessClients.map((c: any) => ({ id: c.uuid, level: 0, alterId: 0 }));
      if (vmessInbound.settings.clients.length === 0) {
        vmessInbound.settings.clients.push({ id: "d2cb8181-233c-4d18-9972-8a1b04db0044", level: 0, alterId: 0 });
      }

      trojanInbound.settings.clients = activeTrojanClients.map((c: any) => ({ password: c.uuid, level: 0 }));
      if (trojanInbound.settings.clients.length === 0) {
        trojanInbound.settings.clients.push({ password: "d2cb8181-233c-4d18-9972-8a1b04db0044", level: 0 });
      }
    }

    fs.writeFileSync(configPath, JSON.stringify(currentConfig, null, 2), "utf8");
    const mainConfigPath = path.join(process.cwd(), "config.json");
    fs.writeFileSync(mainConfigPath, JSON.stringify(currentConfig, null, 2), "utf8");
    addLog(`V2Ray config_${slot}.json synchronized with active clients database.`);
  } catch (err: any) {
    addLog(`Error syncing config_${slot}.json: ${err.message}`);
  }
}

function startV2RayProcessForSlot(slot: "A" | "B"): Promise<boolean> {
  const currentProc = slot === "A" ? v2rayProcessA : v2rayProcessB;
  if (currentProc) {
    addLog(`V2Ray slot ${slot} is already running.`);
    return Promise.resolve(true);
  }

  if (isStartingSlot[slot]) {
    addLog(`V2Ray slot ${slot} is already in the process of starting.`);
    return Promise.resolve(false);
  }

  isStartingSlot[slot] = true;
  addLog(`Starting V2Ray background daemon for slot ${slot}...`);

  return new Promise<boolean>((resolve) => {
    try {
      ensureV2RayBinary();

      if (!fs.existsSync(v2rayPath)) {
        throw new Error("v2ray binary is missing or was not downloaded correctly.");
      }

      syncV2RayConfig(slot);

      const configPath = path.join(process.cwd(), `config_${slot}.json`);
      if (!fs.existsSync(configPath)) {
        throw new Error(`config_${slot}.json is missing from workspace.`);
      }

      const proc = spawn(v2rayPath, ["run", "-config", configPath], {
        cwd: process.cwd(),
        env: { ...process.env }
      });

      if (slot === "A") {
        v2rayProcessA = proc;
      } else {
        v2rayProcessB = proc;
      }

      proc.stdout?.on("data", (data) => {
        const text = data.toString().trim();
        if (text) addLog(`[V2Ray ${slot} STDOUT] ${text}`);
      });

      proc.stderr?.on("data", (data) => {
        const text = data.toString().trim();
        if (text) addLog(`[V2Ray ${slot} STDERR] ${text}`);
      });

      proc.on("error", (err) => {
        addLog(`[V2Ray ${slot} Process Error] ${err.message}`);
      });

      proc.on("exit", (code) => {
        addLog(`[V2Ray ${slot} Process Exit] V2Ray daemon exited with code ${code}`);
        if (slot === "A") v2rayProcessA = null;
        else v2rayProcessB = null;
        isStartingSlot[slot] = false;
      });

      setTimeout(() => {
        isStartingSlot[slot] = false;
        const activeProc = slot === "A" ? v2rayProcessA : v2rayProcessB;
        if (activeProc) {
          const ports = getSlotPorts(slot);
          addLog(`V2Ray daemon slot ${slot} started successfully (PID: ${activeProc.pid}) on ports VLESS:${ports.vless}, VMESS:${ports.vmess}, Trojan:${ports.trojan}`);
          resolve(true);
        } else {
          addLog(`V2Ray daemon slot ${slot} failed to start or crashed on startup.`);
          resolve(false);
        }
      }, 1500);
    } catch (error: any) {
      isStartingSlot[slot] = false;
      addLog(`Failed to start V2Ray process slot ${slot}: ${error?.message || error}`);
      resolve(false);
    }
  });
}

function startV2RayProcess() {
  return startV2RayProcessForSlot(activeSlot).then(() => {});
}

function stopV2RayProcess() {
  addLog("Stopping all V2Ray processes...");
  if (v2rayProcessA) {
    try {
      v2rayProcessA.kill();
      v2rayProcessA = null;
      addLog("V2Ray slot A daemon stopped.");
    } catch (error: any) {
      addLog(`Error stopping V2Ray slot A: ${error?.message || error}`);
    }
  }
  if (v2rayProcessB) {
    try {
      v2rayProcessB.kill();
      v2rayProcessB = null;
      addLog("V2Ray slot B daemon stopped.");
    } catch (error: any) {
      addLog(`Error stopping V2Ray slot B: ${error?.message || error}`);
    }
  }
}

function safeRestartV2Ray(delayMs = 1000) {
  addLog(`Scheduling zero-downtime V2Ray update in ${delayMs}ms...`);
  setTimeout(async () => {
    try {
      const nextSlot = activeSlot === "A" ? "B" : "A";
      addLog(`Preparing zero-downtime hot-swap from slot ${activeSlot} to slot ${nextSlot}...`);

      const started = await startV2RayProcessForSlot(nextSlot);
      if (started) {
        const oldSlot = activeSlot;
        activeSlot = nextSlot;
        addLog(`Successfully hot-swapped active traffic proxy to slot ${activeSlot}!`);

        addLog(`Scheduling graceful shutdown of old slot ${oldSlot} daemon in 25 seconds...`);
        setTimeout(() => {
          try {
            const oldProc = oldSlot === "A" ? v2rayProcessA : v2rayProcessB;
            if (oldProc) {
              addLog(`Teardown: Gracefully terminating old V2Ray daemon slot ${oldSlot} (PID: ${oldProc.pid}).`);
              oldProc.kill();
              if (oldSlot === "A") v2rayProcessA = null;
              else v2rayProcessB = null;
            }
          } catch (err: any) {
            addLog(`Error during graceful teardown of old slot ${oldSlot}: ${err?.message || err}`);
          }
        }, 25000);
      } else {
        addLog(`Failed to start slot ${nextSlot}. Keeping slot ${activeSlot} active.`);
      }
    } catch (err: any) {
      addLog(`Error during safe zero-downtime V2Ray restart: ${err?.message || err}`);
    }
  }, delayMs);
}

// -----------------------------------------------------------------------------
// WebSocket proxy + per-client traffic tracking (unchanged from before --
// this is the real VPN data path, not an "admin interface")
// -----------------------------------------------------------------------------
const wsProxy = httpProxy.createProxyServer({
  target: `ws://127.0.0.1:${V2RAY_PORT}`,
  ws: true,
  changeOrigin: true
});

wsProxy.on("error", (err, req, socket: any) => {
  addLog(`[Proxy Error] ${err.message}`);
  try {
    if (socket && typeof socket.destroy === "function" && !socket.destroyed) {
      socket.destroy();
    }
  } catch (ex: any) {
    addLog(`[Proxy Error Handler Exception] ${ex?.message || ex}`);
  }
});

interface TrafficBatch {
  upload: number;
  download: number;
}
const trafficBuffer: Record<string, TrafficBatch> = {};
const activeSockets: Record<string, Set<any>> = {};

setInterval(() => {
  const now = Date.now();
  for (const clientId of Object.keys(activeSockets)) {
    const sockets = activeSockets[clientId];
    if (sockets) {
      const socketArray = Array.from(sockets);
      for (const s of socketArray) {
        const inactiveTime = now - (s.lastActive || 0);
        if (s.destroyed || (!s.readable && !s.writable) || inactiveTime > 120000) {
          sockets.delete(s);
          try {
            if (!s.destroyed) s.destroy();
          } catch (err) {}
        }
      }
    }
  }
}, 10000);

function accumulateTraffic(clientId: string, bytes: number, type: "upload" | "download") {
  if (!trafficBuffer[clientId]) {
    trafficBuffer[clientId] = { upload: 0, download: 0 };
  }
  trafficBuffer[clientId][type] += bytes;
}

setInterval(() => {
  const clientIds = Object.keys(trafficBuffer);
  if (clientIds.length === 0) return;
  if (!fs.existsSync(clientsFilePath)) return;

  try {
    const data = JSON.parse(fs.readFileSync(clientsFilePath, "utf8"));
    let modified = false;

    for (const id of clientIds) {
      const buffer = trafficBuffer[id];
      if (buffer.upload === 0 && buffer.download === 0) continue;

      const client = data.clients.find((c: any) => c.id === id);
      if (client) {
        client.consumedUpload = (client.consumedUpload || 0) + buffer.upload;
        client.consumedDownload = (client.consumedDownload || 0) + buffer.download;
        modified = true;
      }

      trafficBuffer[id] = { upload: 0, download: 0 };
    }

    if (modified) {
      fs.writeFileSync(clientsFilePath, JSON.stringify(data, null, 2), "utf8");
    }
  } catch (err: any) {
    console.error("Error writing buffered traffic to clients.json:", err);
  }
}, 5000);

setInterval(() => {
  if (!fs.existsSync(clientsFilePath)) return;

  try {
    const db = JSON.parse(fs.readFileSync(clientsFilePath, "utf8"));
    let stateChanged = false;

    for (const client of db.clients) {
      if (!client.enabled) continue;

      const hasExpired = client.expiresAt && new Date(client.expiresAt) < new Date();
      const totalConsumed = (client.consumedUpload || 0) + (client.consumedDownload || 0);
      const limitBytes = (client.limitGB || 0) * 1024 * 1024 * 1024;
      const hasExceededLimit = client.limitGB > 0 && totalConsumed >= limitBytes;

      if (hasExpired || hasExceededLimit) {
        const currentConfig = getV2RayConfig();
        const isInV2Ray = currentConfig?.inbounds?.[0]?.settings?.clients?.some((c: any) => c.id === client.uuid);
        if (isInV2Ray) {
          addLog(`[System Monitor] Disabling active user ${client.name} due to expiration/limit.`);
          stateChanged = true;
        }
      }
    }

    if (stateChanged) {
      syncV2RayConfig();
      stopV2RayProcess();
      setTimeout(() => {
        startV2RayProcess();
      }, 1000);
    }
  } catch (err: any) {
    console.error("Error in background validity monitor:", err);
  }
}, 15000);

function parseVlessUUID(chunk: any): string | null {
  try {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (!buf || buf.length < 23) return null;

    const opcode = buf[0] & 0x0f;
    if (opcode !== 0x02) return null;

    const isMasked = (buf[1] & 0x80) !== 0;
    let payloadLen = buf[1] & 0x7f;
    let maskingKeyOffset = 2;
    let payloadStart = 6;

    if (payloadLen === 126) {
      if (buf.length < 25) return null;
      payloadLen = buf.readUInt16BE(2);
      maskingKeyOffset = 4;
      payloadStart = 8;
    } else if (payloadLen === 127) {
      if (buf.length < 31) return null;
      maskingKeyOffset = 10;
      payloadStart = 14;
    }

    if (buf.length < payloadStart + 17) return null;

    const uuidBytes = Buffer.alloc(16);
    if (isMasked) {
      const maskingKey = buf.slice(maskingKeyOffset, maskingKeyOffset + 4);
      for (let i = 0; i < 16; i++) {
        const maskedByte = buf[payloadStart + 1 + i];
        const maskKeyByte = maskingKey[(1 + i) % 4];
        uuidBytes[i] = maskedByte ^ maskKeyByte;
      }
    } else {
      for (let i = 0; i < 16; i++) {
        uuidBytes[i] = buf[payloadStart + 1 + i];
      }
    }

    const hex = uuidBytes.toString("hex");
    if (hex.length !== 32) return null;

    return [hex.substring(0, 8), hex.substring(8, 12), hex.substring(12, 16), hex.substring(16, 20), hex.substring(20, 32)].join("-");
  } catch (err) {
    return null;
  }
}

server.on("upgrade", (req, socket, head) => {
  try {
    const url = req.url || "";
    const defaultPath = getV2RayPath();

    const clients = getPersistedClients();
    const matchingClient = clients.find((c: any) => {
      try {
        const parsedUrl = new URL(url, `http://${req.headers.host || "localhost"}`);
        const pathname = parsedUrl.pathname;
        return c.enabled && pathname === c.path;
      } catch (e) {
        return c.enabled && url.split("?")[0] === c.path;
      }
    });

    const isDefaultPath = url.startsWith(defaultPath);

    if (matchingClient || isDefaultPath) {
      if (matchingClient) {
        if (matchingClient.expiresAt && new Date(matchingClient.expiresAt) < new Date()) {
          addLog(`[Proxy Denied] Client ${matchingClient.name} has expired (matched by path).`);
          socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
          socket.destroy();
          return;
        }

        const totalConsumed = (matchingClient.consumedUpload || 0) + (matchingClient.consumedDownload || 0);
        const limitBytes = (matchingClient.limitGB || 0) * 1024 * 1024 * 1024;
        if (matchingClient.limitGB > 0 && totalConsumed >= limitBytes) {
          addLog(`[Proxy Denied] Client ${matchingClient.name} exceeded traffic limit (${matchingClient.limitGB} GB).`);
          socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
          socket.destroy();
          return;
        }

        addLog(`[Proxy] Upgrading WebSocket connection for client ${matchingClient.name} (${matchingClient.path}) -> V2Ray`);
      } else {
        addLog(`[Proxy] Upgrading general/fallback WebSocket connection (${url}) -> V2Ray`);
      }

      req.url = defaultPath;

      let detectedClientId: string | null = matchingClient ? matchingClient.id : null;
      const sockObj = socket as any;
      sockObj.lastActive = Date.now();
      sockObj.vlessUuidParsed = matchingClient && matchingClient.protocol !== "vless" ? true : false;

      if (detectedClientId) {
        if (!activeSockets[detectedClientId]) activeSockets[detectedClientId] = new Set();
        activeSockets[detectedClientId].add(sockObj);
      }

      sockObj.setKeepAlive?.(true, 5000);
      sockObj.setTimeout?.(45000);

      const cleanupSocket = () => {
        if (detectedClientId && activeSockets[detectedClientId]) {
          activeSockets[detectedClientId].delete(sockObj);
        }
      };

      socket.on("close", cleanupSocket);
      socket.on("end", cleanupSocket);
      socket.on("error", cleanupSocket);
      socket.on("timeout", () => {
        const clientName = matchingClient ? matchingClient.name : detectedClientId ? "Detected User" : "Unknown";
        addLog(`[Proxy] Socket timeout of 45s reached for client ${clientName}. Destroying connection.`);
        try {
          socket.destroy();
        } catch (err) {}
      });

      const originalEmit = socket.emit;
      socket.emit = function (event: string | symbol, ...args: any[]) {
        if (event === "data") {
          sockObj.lastActive = Date.now();
          const chunk = args[0];
          if (chunk && chunk.length) {
            if (!sockObj.vlessUuidParsed) {
              const parsedUuid = parseVlessUUID(chunk);
              if (parsedUuid) {
                sockObj.vlessUuidParsed = true;
                const currentClients = getPersistedClients();
                const matchedClient = currentClients.find((c: any) => c.uuid.toLowerCase() === parsedUuid.toLowerCase());
                if (matchedClient) {
                  if (matchedClient.expiresAt && new Date(matchedClient.expiresAt) < new Date()) {
                    addLog(`[Proxy Denied] Automatically detected client ${matchedClient.name} has expired. Destroying socket.`);
                    try {
                      socket.destroy();
                    } catch (err) {}
                    return false;
                  }
                  const clientConsumed = (matchedClient.consumedUpload || 0) + (matchedClient.consumedDownload || 0);
                  const clientLimitBytes = (matchedClient.limitGB || 0) * 1024 * 1024 * 1024;
                  if (matchedClient.limitGB > 0 && clientConsumed >= clientLimitBytes) {
                    addLog(`[Proxy Denied] Automatically detected client ${matchedClient.name} exceeded traffic limit. Destroying socket.`);
                    try {
                      socket.destroy();
                    } catch (err) {}
                    return false;
                  }

                  if (detectedClientId && detectedClientId !== matchedClient.id) {
                    if (activeSockets[detectedClientId]) activeSockets[detectedClientId].delete(sockObj);
                  }
                  detectedClientId = matchedClient.id;
                  if (!activeSockets[detectedClientId]) activeSockets[detectedClientId] = new Set();
                  activeSockets[detectedClientId].add(sockObj);
                  addLog(`[Proxy] Automatically matched UUID ${parsedUuid} to client: ${matchedClient.name}. Active connections updated.`);
                }
              }
            }

            if (detectedClientId) {
              accumulateTraffic(detectedClientId, chunk.length, "upload");
            }
          }
        } else if (event === "close" || event === "end" || event === "error") {
          cleanupSocket();
        }
        return originalEmit.apply(this, arguments as any);
      };

      const originalWrite = socket.write;
      socket.write = function (chunk: any, encoding?: any, callback?: any) {
        sockObj.lastActive = Date.now();
        if (chunk && detectedClientId) {
          accumulateTraffic(detectedClientId, chunk.length, "download");
        }
        try {
          if (!socket.destroyed && socket.writable) {
            return originalWrite.apply(this, arguments as any);
          }
        } catch (err: any) {
          addLog(`[Proxy socket.write error] ${err?.message || err}`);
        }
        if (typeof callback === "function") callback();
        return false;
      };

      const ports = getSlotPorts(activeSlot);
      let targetPort = ports.vless;
      if (matchingClient) {
        if (matchingClient.protocol === "vmess") targetPort = ports.vmess;
        else if (matchingClient.protocol === "trojan") targetPort = ports.trojan;
      }
      wsProxy.ws(req, socket, head, { target: `ws://127.0.0.1:${targetPort}` });
    } else {
      addLog(`[Proxy Info] Unknown WS connection upgrade request: ${url}`);
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
    }
  } catch (err: any) {
    addLog(`[Proxy Upgrade Handler Error] ${err?.message || err}`);
    try {
      if (socket && !socket.destroyed) socket.destroy();
    } catch (e) {}
  }
});

// =============================================================================
// Telegram bot -- the ONLY admin interface
// =============================================================================
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "8184142781:AAG0d38hWzsBa3o5y-2SxKEU3VRlLs2-xPM";
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || "1726923679";
const TELEGRAM_API_BASE = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

const DURATION_LABELS: Record<string, string> = {
  minutes: "دقائق",
  hours: "ساعات",
  days: "أيام",
  months: "أشهر",
  years: "سنوات",
  unlimited: "غير محدود"
};

const PROTOCOL_LABELS: Record<string, string> = {
  vless: "VLESS",
  vmess: "VMess",
  trojan: "Trojan"
};

async function telegramCall(method: string, payload: Record<string, any>) {
  try {
    const res = await fetch(`${TELEGRAM_API_BASE}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!data.ok) {
      addLog(`Telegram API error on ${method}: ${JSON.stringify(data)}`);
    }
    return data;
  } catch (e: any) {
    addLog(`Telegram API request failed (${method}): ${e?.message || e}`);
    return null;
  }
}

async function sendMessage(text: string, replyMarkup?: any) {
  return telegramCall("sendMessage", {
    chat_id: TELEGRAM_ADMIN_CHAT_ID,
    text,
    parse_mode: "Markdown",
    reply_markup: replyMarkup
  });
}

async function editMessage(messageId: number, text: string, replyMarkup?: any) {
  return telegramCall("editMessageText", {
    chat_id: TELEGRAM_ADMIN_CHAT_ID,
    message_id: messageId,
    text,
    parse_mode: "Markdown",
    reply_markup: replyMarkup
  });
}

async function answerCallbackQuery(callbackQueryId: string, text?: string) {
  return telegramCall("answerCallbackQuery", { callback_query_id: callbackQueryId, text, show_alert: false });
}

async function sendQrPhoto(link: string, caption: string) {
  try {
    const buffer = await QRCode.toBuffer(link, { type: "png", width: 400, margin: 1 });
    const form = new FormData();
    form.append("chat_id", TELEGRAM_ADMIN_CHAT_ID);
    form.append("caption", caption);
    form.append("parse_mode", "Markdown");
    form.append("photo", new Blob([buffer], { type: "image/png" }), "config-qr.png");

    const res = await fetch(`${TELEGRAM_API_BASE}/sendPhoto`, { method: "POST", body: form as any });
    const data = await res.json();
    if (!data.ok) addLog(`Telegram sendPhoto error: ${JSON.stringify(data)}`);
    return data;
  } catch (e: any) {
    addLog(`Failed to generate/send QR code: ${e?.message || e}`);
    return null;
  }
}

// -----------------------------------------------------------------------------
// Config-link builder (replaces the old browser-side getConfigUrl)
// -----------------------------------------------------------------------------
async function getPublicHost(): Promise<string> {
  // 1) Explicit manual override always wins, if provided.
  const raw = process.env.APP_URL;
  if (raw) {
    try {
      const u = new URL(raw.includes("://") ? raw : `https://${raw}`);
      return u.hostname;
    } catch {
      return raw.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    }
  }

  // 2) Already auto-detected (from a prior request or the metadata server).
  if (cachedPublicHost) return cachedPublicHost;

  // 3) Replit dev domain (available as a runtime env var on Replit).
  const replitDomain = process.env.REPLIT_DEV_DOMAIN;
  if (replitDomain) return replitDomain;

  // 4) Try the metadata server once more, in case startup detection hasn't
  //    resolved yet (e.g. this is the very first call, right after boot).
  const detected = await detectCloudRunHostFromMetadata();
  if (detected) {
    rememberPublicHost(detected);
    return detected;
  }

  // 5) Nothing detected yet -- placeholder. This resolves itself automatically
  //    on Cloud Run as soon as either the metadata lookup succeeds or a single
  //    request comes in through the public run.app URL.
  return "YOUR-DOMAIN.example.com";
}

async function buildConfigLink(client: any): Promise<string> {
  const host = await getPublicHost();
  const pathWithSlash = client.path.startsWith("/") ? client.path : "/" + client.path;
  const label = encodeURIComponent(`Moon_${client.name}`);

  if (client.protocol === "vmess") {
    const vmessObj = {
      v: "2",
      ps: `Moon_${client.name}`,
      add: host,
      port: 443,
      id: client.uuid,
      aid: "0",
      scy: "auto",
      net: "ws",
      type: "none",
      host,
      path: pathWithSlash,
      tls: "tls",
      sni: host
    };
    const b64 = Buffer.from(JSON.stringify(vmessObj), "utf8").toString("base64");
    return `vmess://${b64}`;
  }

  if (client.protocol === "trojan") {
    return `trojan://${client.uuid}@${host}:443?path=${encodeURIComponent(pathWithSlash)}&security=tls&type=ws&host=${host}&sni=${host}#${label}`;
  }

  return `vless://${client.uuid}@${host}:443?path=${encodeURIComponent(pathWithSlash)}&security=tls&encryption=none&type=ws&host=${host}&sni=${host}#${label}`;
}

function computeExpiresAt(duration: string, value: number): string | null {
  if (duration === "unlimited" || !value || value <= 0) return null;
  const expDate = new Date();
  if (duration === "minutes") expDate.setMinutes(expDate.getMinutes() + value);
  else if (duration === "hours") expDate.setHours(expDate.getHours() + value);
  else if (duration === "days") expDate.setDate(expDate.getDate() + value);
  else if (duration === "months") expDate.setMonth(expDate.getMonth() + value);
  else if (duration === "years") expDate.setFullYear(expDate.getFullYear() + value);
  return expDate.toISOString();
}

function generateUniquePath(existingClients: any[]): string {
  let candidate = "";
  do {
    candidate = "/" + crypto.randomBytes(4).toString("hex");
  } while (existingClients.some((c) => c.path === candidate));
  return candidate;
}

function formatBytes(bytes: number): string {
  if (!bytes) return "0 MB";
  const gb = bytes / (1024 * 1024 * 1024);
  if (gb >= 1) return gb.toFixed(2) + " GB";
  const mb = bytes / (1024 * 1024);
  return mb.toFixed(1) + " MB";
}

function getClientStatusLabel(c: any): string {
  if (!c.enabled) return "⏸ متوقف";
  if (c.expiresAt && new Date(c.expiresAt) < new Date()) return "⌛ منتهي";
  const consumed = (c.consumedUpload || 0) + (c.consumedDownload || 0);
  const limitBytes = (c.limitGB || 0) * 1024 * 1024 * 1024;
  if (c.limitGB > 0 && consumed >= limitBytes) return "🚫 تجاوز الحد";
  return "✅ نشط";
}

// -----------------------------------------------------------------------------
// Menus
// -----------------------------------------------------------------------------
function mainMenuKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: "➕ إنشاء تكوين", callback_data: "create" },
        { text: "📋 التكوينات", callback_data: "list" }
      ],
      [
        { text: "⚙️ حالة الخادم", callback_data: "status" },
        { text: "📜 السجلات", callback_data: "logs" }
      ],
      [
        { text: "▶️ تشغيل", callback_data: "start_v2ray" },
        { text: "⏹ إيقاف", callback_data: "stop_v2ray" },
        { text: "🔄 إعادة تشغيل", callback_data: "restart_v2ray" }
      ]
    ]
  };
}

function protocolKeyboard(prefix: string) {
  return {
    inline_keyboard: [
      [
        { text: "VLESS", callback_data: `${prefix}:vless` },
        { text: "VMess", callback_data: `${prefix}:vmess` },
        { text: "Trojan", callback_data: `${prefix}:trojan` }
      ],
      [{ text: "❌ إلغاء", callback_data: "cancel" }]
    ]
  };
}

function durationKeyboard(prefix: string) {
  return {
    inline_keyboard: [
      [
        { text: "دقائق", callback_data: `${prefix}:minutes` },
        { text: "ساعات", callback_data: `${prefix}:hours` }
      ],
      [
        { text: "أيام", callback_data: `${prefix}:days` },
        { text: "أشهر", callback_data: `${prefix}:months` },
        { text: "سنوات", callback_data: `${prefix}:years` }
      ],
      [{ text: "♾️ غير محدود", callback_data: `${prefix}:unlimited` }],
      [{ text: "❌ إلغاء", callback_data: "cancel" }]
    ]
  };
}

async function showMainMenu(intro = "📡 *لوحة تحكم خادم V2Ray*\nاختر إجراءً:") {
  await sendMessage(intro, mainMenuKeyboard());
}

// -----------------------------------------------------------------------------
// Conversation state (single admin -> single in-memory session is enough)
// -----------------------------------------------------------------------------
type ConvoStep =
  | "idle"
  | "awaiting_name"
  | "awaiting_duration_value"
  | "awaiting_limit"
  | "awaiting_edit_duration_value"
  | "awaiting_edit_limit";

let convo: { step: ConvoStep; data: Record<string, any> } = { step: "idle", data: {} };

function resetConvo() {
  convo = { step: "idle", data: {} };
}

// -----------------------------------------------------------------------------
// Feature: create client
// -----------------------------------------------------------------------------
async function startCreateFlow() {
  resetConvo();
  await sendMessage("🧩 *إنشاء تكوين جديد*\n\nاختر البروتوكول (يمكن ضبط مدة صلاحية مختلفة لكل بروتوكول):", protocolKeyboard("proto"));
}

async function onProtocolChosen(protocol: string) {
  convo = { step: "awaiting_name", data: { protocol } };
  await sendMessage(`تم اختيار البروتوكول: *${PROTOCOL_LABELS[protocol]}*\n\n✏️ أرسل الآن اسم العميل (Client Name):`);
}

async function onNameProvided(name: string) {
  convo.data.name = name.trim();
  convo.step = "idle";
  await sendMessage(
    `⏳ اختر مدة صلاحية هذا التكوين (${PROTOCOL_LABELS[convo.data.protocol]}):`,
    durationKeyboard("duration")
  );
}

async function onDurationUnitChosen(unit: string) {
  convo.data.duration = unit;
  if (unit === "unlimited") {
    convo.data.durationValue = 0;
    convo.step = "awaiting_limit";
    await sendMessage("💾 أدخل الحد الأقصى للاستهلاك بالجيجابايت (اكتب 0 لغير محدود):");
  } else {
    convo.step = "awaiting_duration_value";
    await sendMessage(`🔢 أدخل القيمة العددية للمدة بالـ ${DURATION_LABELS[unit]} (مثال: 30):`);
  }
}

async function onDurationValueProvided(text: string) {
  const value = parseInt(text.trim(), 10);
  if (isNaN(value) || value <= 0) {
    await sendMessage("⚠️ الرجاء إرسال رقم صحيح أكبر من 0.");
    return;
  }
  convo.data.durationValue = value;
  convo.step = "awaiting_limit";
  await sendMessage("💾 أدخل الحد الأقصى للاستهلاك بالجيجابايت (اكتب 0 لغير محدود):");
}

async function onLimitProvidedAndFinalize(text: string) {
  const value = parseFloat(text.trim());
  const limitGB = isNaN(value) || value < 0 ? 0 : value;

  const clients = getPersistedClients();
  const uuid = crypto.randomUUID();
  const clientPath = generateUniquePath(clients);
  const expiresAt = computeExpiresAt(convo.data.duration, convo.data.durationValue || 0);

  const newClient = {
    id: "client_" + Math.random().toString(36).substring(2),
    name: convo.data.name,
    protocol: convo.data.protocol,
    uuid,
    path: clientPath,
    limitGB,
    consumedUpload: 0,
    consumedDownload: 0,
    duration: convo.data.duration,
    durationValue: convo.data.durationValue || 0,
    createdAt: new Date().toISOString(),
    expiresAt,
    enabled: true
  };

  clients.push(newClient);
  savePersistedClients(clients);
  addLog(`Bot admin created new ${newClient.protocol} client: ${newClient.name}`);
  safeRestartV2Ray(1000);
  resetConvo();

  const link = await buildConfigLink(newClient);
  const durationLabel = newClient.duration === "unlimited" ? "غير محدود" : `${newClient.durationValue} ${DURATION_LABELS[newClient.duration]}`;

  const summary =
    `✅ *تم إنشاء التكوين بنجاح!*\n\n` +
    `👤 الاسم: ${newClient.name}\n` +
    `🔌 البروتوكول: ${PROTOCOL_LABELS[newClient.protocol]}\n` +
    `⏳ الصلاحية: ${durationLabel}\n` +
    `💾 الحد: ${limitGB > 0 ? limitGB + " GB" : "غير محدود"}\n\n` +
    `🔗 رابط التكوين:\n\`${link}\``;

  await sendMessage(summary, { inline_keyboard: [[{ text: "🔙 القائمة الرئيسية", callback_data: "menu" }]] });
  await sendQrPhoto(link, `QR الخاص بـ ${newClient.name}`);
}

// -----------------------------------------------------------------------------
// Feature: list / view / edit / delete clients
// -----------------------------------------------------------------------------
async function listClients() {
  const clients = getPersistedClients();
  if (clients.length === 0) {
    await sendMessage("لا يوجد أي تكوينات بعد. استخدم زر «➕ إنشاء تكوين» لإضافة أول عميل.", {
      inline_keyboard: [[{ text: "➕ إنشاء تكوين", callback_data: "create" }]]
    });
    return;
  }

  const rows = clients.map((c: any) => [
    { text: `${getClientStatusLabel(c)} ${c.name} (${PROTOCOL_LABELS[c.protocol] || "VLESS"})`, callback_data: `view:${c.id}` }
  ]);
  rows.push([{ text: "🔙 القائمة الرئيسية", callback_data: "menu" }]);

  await sendMessage(`📋 *قائمة التكوينات* (${clients.length}):`, { inline_keyboard: rows });
}

function findClient(id: string) {
  const clients = getPersistedClients();
  return { clients, client: clients.find((c: any) => c.id === id) };
}

async function viewClient(id: string) {
  const { client } = findClient(id);
  if (!client) {
    await sendMessage("⚠️ لم يتم العثور على هذا التكوين (ربما تم حذفه).");
    return;
  }

  const link = await buildConfigLink(client);
  const durationLabel = client.duration === "unlimited" ? "غير محدود" : `${client.durationValue} ${DURATION_LABELS[client.duration]}`;
  const consumed = formatBytes((client.consumedUpload || 0) + (client.consumedDownload || 0));
  const limitLabel = client.limitGB > 0 ? `${client.limitGB} GB` : "غير محدود";

  const details =
    `🔎 *تفاصيل التكوين*\n\n` +
    `👤 الاسم: ${client.name}\n` +
    `🔌 البروتوكول: ${PROTOCOL_LABELS[client.protocol] || "VLESS"}\n` +
    `📶 الحالة: ${getClientStatusLabel(client)}\n` +
    `⏳ الصلاحية: ${durationLabel}${client.expiresAt ? `\n📅 تنتهي في: ${client.expiresAt}` : ""}\n` +
    `📊 الاستهلاك: ${consumed} / ${limitLabel}\n\n` +
    `🔗 رابط التكوين:\n\`${link}\``;

  await sendMessage(details, {
    inline_keyboard: [
      [
        { text: client.enabled ? "⏸ إيقاف" : "▶️ تفعيل", callback_data: `toggle:${client.id}` },
        { text: "✏️ تعديل المدة", callback_data: `editdur:${client.id}` }
      ],
      [
        { text: "✏️ تعديل الحد", callback_data: `editlimit:${client.id}` },
        { text: "🗑 حذف", callback_data: `delete:${client.id}` }
      ],
      [{ text: "🔙 القائمة الرئيسية", callback_data: "menu" }]
    ]
  });
  await sendQrPhoto(link, `QR الخاص بـ ${client.name}`);
}

async function toggleClient(id: string) {
  const { clients, client } = findClient(id);
  if (!client) return;
  client.enabled = !client.enabled;
  savePersistedClients(clients);
  addLog(`Bot admin ${client.enabled ? "enabled" : "disabled"} client: ${client.name}`);
  safeRestartV2Ray(1000);
  await sendMessage(`${client.enabled ? "▶️ تم تفعيل" : "⏸ تم إيقاف"} التكوين: ${client.name}`);
  await viewClient(id);
}

async function askDeleteConfirmation(id: string) {
  const { client } = findClient(id);
  if (!client) return;
  await sendMessage(`⚠️ هل أنت متأكد من حذف التكوين *${client.name}*؟ لا يمكن التراجع عن هذا الإجراء.`, {
    inline_keyboard: [
      [
        { text: "✅ نعم، احذف", callback_data: `confirmdelete:${id}` },
        { text: "❌ إلغاء", callback_data: "cancel" }
      ]
    ]
  });
}

async function deleteClient(id: string) {
  const { clients, client } = findClient(id);
  if (!client) {
    await sendMessage("⚠️ لم يتم العثور على هذا التكوين.");
    return;
  }
  const filtered = clients.filter((c: any) => c.id !== id);
  savePersistedClients(filtered);
  addLog(`Bot admin deleted client: ${client.name}`);
  safeRestartV2Ray(1000);
  await sendMessage(`🗑 تم حذف التكوين: ${client.name}`, { inline_keyboard: [[{ text: "🔙 القائمة الرئيسية", callback_data: "menu" }]] });
}

async function startEditDurationFlow(id: string) {
  const { client } = findClient(id);
  if (!client) return;
  await sendMessage(`⏳ اختر مدة صلاحية جديدة لـ *${client.name}*:`, durationKeyboard(`editdurunit:${id}`));
}

async function onEditDurationUnitChosen(id: string, unit: string) {
  if (unit === "unlimited") {
    const { clients, client } = findClient(id);
    if (!client) return;
    client.duration = "unlimited";
    client.durationValue = 0;
    client.expiresAt = null;
    savePersistedClients(clients);
    addLog(`Bot admin set client ${client.name} duration to unlimited.`);
    safeRestartV2Ray(1000);
    await sendMessage(`✅ تم تحديث مدة صلاحية *${client.name}* إلى غير محدود.`);
    await viewClient(id);
  } else {
    convo = { step: "awaiting_edit_duration_value", data: { id, duration: unit } };
    await sendMessage(`🔢 أدخل القيمة العددية للمدة بالـ ${DURATION_LABELS[unit]}:`);
  }
}

async function onEditDurationValueProvided(text: string) {
  const value = parseInt(text.trim(), 10);
  if (isNaN(value) || value <= 0) {
    await sendMessage("⚠️ الرجاء إرسال رقم صحيح أكبر من 0.");
    return;
  }
  const { id, duration } = convo.data;
  const { clients, client } = findClient(id);
  resetConvo();
  if (!client) {
    await sendMessage("⚠️ لم يتم العثور على هذا التكوين.");
    return;
  }
  client.duration = duration;
  client.durationValue = value;
  client.expiresAt = computeExpiresAt(duration, value);
  savePersistedClients(clients);
  addLog(`Bot admin updated client ${client.name} duration to ${value} ${duration}.`);
  safeRestartV2Ray(1000);
  await sendMessage(`✅ تم تحديث مدة صلاحية *${client.name}*.`);
  await viewClient(id);
}

async function startEditLimitFlow(id: string) {
  const { client } = findClient(id);
  if (!client) return;
  convo = { step: "awaiting_edit_limit", data: { id } };
  await sendMessage(`💾 أدخل الحد الأقصى الجديد للاستهلاك بالجيجابايت لـ *${client.name}* (0 = غير محدود):`);
}

async function onEditLimitProvided(text: string) {
  const value = parseFloat(text.trim());
  const limitGB = isNaN(value) || value < 0 ? 0 : value;
  const { id } = convo.data;
  const { clients, client } = findClient(id);
  resetConvo();
  if (!client) {
    await sendMessage("⚠️ لم يتم العثور على هذا التكوين.");
    return;
  }
  client.limitGB = limitGB;
  savePersistedClients(clients);
  addLog(`Bot admin updated client ${client.name} limit to ${limitGB} GB.`);
  safeRestartV2Ray(1000);
  await sendMessage(`✅ تم تحديث حد الاستهلاك لـ *${client.name}*.`);
  await viewClient(id);
}

// -----------------------------------------------------------------------------
// Feature: server status / logs / control
// -----------------------------------------------------------------------------
function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d > 0) parts.push(`${d}ي`);
  if (h > 0) parts.push(`${h}س`);
  parts.push(`${m}د`);
  return parts.join(" ");
}

async function sendServerStatus() {
  const running = v2rayProcessA !== null || v2rayProcessB !== null;
  const clients = getPersistedClients();
  const active = clients.filter((c: any) => getClientStatusLabel(c) === "✅ نشط").length;
  const expired = clients.filter((c: any) => getClientStatusLabel(c) === "⌛ منتهي").length;
  const disabled = clients.filter((c: any) => getClientStatusLabel(c) === "⏸ متوقف").length;
  const overLimit = clients.filter((c: any) => getClientStatusLabel(c) === "🚫 تجاوز الحد").length;

  let diskLine = "غير متاح";
  try {
    if (typeof fs.statfsSync === "function") {
      const stats = fs.statfsSync("/");
      const total = stats.bsize * stats.blocks;
      const free = stats.bsize * stats.bavail;
      const used = total - free;
      diskLine = `${formatBytes(used)} / ${formatBytes(total)}`;
    }
  } catch (e) {
    // ignore, keep default
  }

  const totalMem = os.totalmem();
  const freeMem = os.freemem();

  const text =
    `⚙️ *حالة الخادم*\n\n` +
    `🟢 V2Ray: ${running ? "يعمل ✅" : "متوقف ⛔"}\n` +
    `⏱ مدة التشغيل: ${formatUptime(process.uptime())}\n` +
    `💽 القرص: ${diskLine}\n` +
    `🧠 الذاكرة: ${formatBytes(totalMem - freeMem)} / ${formatBytes(totalMem)}\n\n` +
    `👥 إجمالي التكوينات: ${clients.length}\n` +
    `✅ نشط: ${active} | ⌛ منتهي: ${expired} | ⏸ متوقف: ${disabled} | 🚫 تجاوز الحد: ${overLimit}`;

  await sendMessage(text, { inline_keyboard: [[{ text: "🔙 القائمة الرئيسية", callback_data: "menu" }]] });
}

async function sendRecentLogs() {
  const recent = logs.slice(-25).join("\n") || "لا توجد سجلات بعد.";
  const trimmed = recent.length > 3500 ? recent.slice(recent.length - 3500) : recent;
  await sendMessage(`📜 *آخر السجلات:*\n\`\`\`\n${trimmed}\n\`\`\``, {
    inline_keyboard: [[{ text: "🔙 القائمة الرئيسية", callback_data: "menu" }]]
  });
}

// -----------------------------------------------------------------------------
// Update dispatcher (long-polling, admin-only)
// -----------------------------------------------------------------------------
async function handleCallbackData(data: string) {
  if (data === "menu") {
    resetConvo();
    await showMainMenu();
    return;
  }
  if (data === "cancel") {
    resetConvo();
    await showMainMenu("❌ تم الإلغاء.");
    return;
  }
  if (data === "create") {
    await startCreateFlow();
    return;
  }
  if (data === "list") {
    await listClients();
    return;
  }
  if (data === "status") {
    await sendServerStatus();
    return;
  }
  if (data === "logs") {
    await sendRecentLogs();
    return;
  }
  if (data === "start_v2ray") {
    await sendMessage("▶️ جارٍ تشغيل V2Ray...");
    startV2RayProcess();
    return;
  }
  if (data === "stop_v2ray") {
    await sendMessage("⏹ جارٍ إيقاف V2Ray...");
    stopV2RayProcess();
    return;
  }
  if (data === "restart_v2ray") {
    await sendMessage("🔄 جارٍ إعادة تشغيل V2Ray (بدون انقطاع)...");
    safeRestartV2Ray(500);
    return;
  }

  const [action, ...rest] = data.split(":");
  const arg1 = rest[0];
  const arg2 = rest[1];

  if (action === "proto") {
    await onProtocolChosen(arg1);
  } else if (action === "duration") {
    await onDurationUnitChosen(arg1);
  } else if (action === "view") {
    await viewClient(arg1);
  } else if (action === "toggle") {
    await toggleClient(arg1);
  } else if (action === "delete") {
    await askDeleteConfirmation(arg1);
  } else if (action === "confirmdelete") {
    await deleteClient(arg1);
  } else if (action === "editdur") {
    await startEditDurationFlow(arg1);
  } else if (action === "editdurunit") {
    await onEditDurationUnitChosen(arg1, arg2);
  } else if (action === "editlimit") {
    await startEditLimitFlow(arg1);
  }
}

async function handleTextMessage(text: string) {
  const trimmed = text.trim();

  if (trimmed === "/start" || trimmed === "/menu") {
    resetConvo();
    await showMainMenu("👋 أهلاً بك في بوت إدارة خادم V2Ray.\nاختر إجراءً من القائمة:");
    return;
  }
  if (trimmed === "/cancel") {
    resetConvo();
    await showMainMenu("❌ تم إلغاء العملية الحالية.");
    return;
  }

  switch (convo.step) {
    case "awaiting_name":
      await onNameProvided(trimmed);
      return;
    case "awaiting_duration_value":
      await onDurationValueProvided(trimmed);
      return;
    case "awaiting_limit":
      await onLimitProvidedAndFinalize(trimmed);
      return;
    case "awaiting_edit_duration_value":
      await onEditDurationValueProvided(trimmed);
      return;
    case "awaiting_edit_limit":
      await onEditLimitProvided(trimmed);
      return;
    default:
      await showMainMenu();
      return;
  }
}

let telegramUpdateOffset = 0;
async function pollTelegramUpdates() {
  try {
    const data = await telegramCall("getUpdates", {
      offset: telegramUpdateOffset,
      timeout: 25,
      allowed_updates: ["callback_query", "message"]
    });

    if (data?.ok && Array.isArray(data.result)) {
      for (const update of data.result) {
        telegramUpdateOffset = update.update_id + 1;

        if (update.callback_query) {
          const cq = update.callback_query;
          const fromId = String(cq.from?.id || "");
          await answerCallbackQuery(cq.id);
          if (fromId !== String(TELEGRAM_ADMIN_CHAT_ID)) {
            addLog(`Ignored Telegram callback from unauthorized chat id: ${fromId}`);
            continue;
          }
          try {
            await handleCallbackData(cq.data || "");
          } catch (e: any) {
            addLog(`Error handling callback "${cq.data}": ${e?.message || e}`);
          }
        }

        if (update.message?.text) {
          const fromId = String(update.message.from?.id || "");
          if (fromId !== String(TELEGRAM_ADMIN_CHAT_ID)) {
            addLog(`Ignored Telegram message from unauthorized chat id: ${fromId}`);
            await telegramCall("sendMessage", { chat_id: fromId, text: "🚫 هذا البوت خاص ولا يمكنك استخدامه." });
            continue;
          }
          try {
            await handleTextMessage(update.message.text);
          } catch (e: any) {
            addLog(`Error handling message: ${e?.message || e}`);
          }
        }
      }
    }
  } catch (e: any) {
    addLog(`Telegram polling error: ${e?.message || e}`);
  } finally {
    setImmediate(pollTelegramUpdates);
  }
}

// -----------------------------------------------------------------------------
// Minimal HTTP surface: just a health-check route for Cloud Run / Docker.
// There is intentionally no other route here -- all administration happens
// through the Telegram bot above.
// -----------------------------------------------------------------------------
app.get("/", (req, res) => {
  res.status(200).send("V2Ray server is running. Administration is done via the Telegram bot only.");
});

// -----------------------------------------------------------------------------
// Bootstrap
// -----------------------------------------------------------------------------
async function startServer() {
  initClientsDB();
  syncV2RayConfig();

  // Delete any active webhook so long-polling works correctly.
  try {
    await telegramCall("deleteWebhook", { drop_pending_updates: false });
    addLog("Telegram webhook cleared.");
  } catch (e: any) {
    addLog(`Failed to clear Telegram webhook (non-fatal): ${e?.message || e}`);
  }

  pollTelegramUpdates();
  addLog("Telegram admin bot listener started.");

  setTimeout(() => {
    startV2RayProcess();
  }, 2000);

  server.listen(PORT, "0.0.0.0", () => {
    addLog(`Health-check HTTP server listening on http://0.0.0.0:${PORT}`);
  });

  sendMessage("🤖 *تم تشغيل بوت إدارة خادم V2Ray بنجاح.*\nأرسل /start لعرض القائمة الرئيسية.");
}

startServer();
