// index.js - Status API: nhận WEBHOOK_URL (vault) + messageId, timeout thì PATCH Disconnected

import "dotenv/config";
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());

// === ENV ===
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "CHANGE_THIS_TO_A_LONG_SECRET";
const HEARTBEAT_TIMEOUT_MS = Number(process.env.HEARTBEAT_TIMEOUT_MS || 15000);

// Supabase client (dùng để đọc webhook_enc giống vault)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

// === Giải mã webhook_enc giống bên vault ===
function getKey() {
  return crypto.createHash("sha256").update(String(ENCRYPTION_KEY)).digest(); // 32 bytes
}

function decryptWebhook(b64) {
  const buf = Buffer.from(b64, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", getKey(), iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString("utf8");
}

// === Resolve: từ WEBHOOK_URL (vault hoặc webhook thật) -> webhook Discord ===
async function resolveWebhook(webhookUrlOrVault) {
  if (!webhookUrlOrVault) return null;

  try {
    const u = new URL(webhookUrlOrVault);

    // Nếu đã là webhook Discord thật thì dùng luôn
    if (
      (/discord(app)?\.com$/).test(u.hostname) &&
      u.pathname.includes("/api/webhooks/")
    ) {
      return webhookUrlOrVault;
    }

    // Nếu là vault: .../api/hit/wh_xxx
    if (u.pathname.includes("/api/hit/wh_")) {
      const m = u.pathname.match(/wh_[0-9a-zA-Z]+/);
      if (!m) return null;
      const vaultId = m[0];

      const { data, error } = await supabase
        .from("webhooks")
        .select("webhook_enc")
        .eq("id", vaultId)
        .maybeSingle();

      if (error || !data || !data.webhook_enc) {
        console.error("[Status] resolveWebhook supabase error", error || data);
        return null;
      }

      try {
        const real = decryptWebhook(data.webhook_enc); // https://discord.com/api/webhooks/...
        return real;
      } catch (e) {
        console.error("[Status] decryptWebhook error", e);
        return null;
      }
    }
  } catch (e) {
    // webhookUrlOrVault không parse được như URL => có thể là direct webhook
    console.error("[Status] resolveWebhook parse error", e);
  }

  // Fallback: coi như đã là webhook thật
  return webhookUrlOrVault;
}

// === PATCH message -> Disconnected ===
async function patchMessageDisconnected(webhookKey, messageId, channelId, embed) {
  const webhookUrl = await resolveWebhook(webhookKey);
  if (!webhookUrl) {
    throw new Error("Cannot resolve webhook");
  }

  const newEmbed = JSON.parse(JSON.stringify(embed || {}));

  if (!Array.isArray(newEmbed.fields)) {
    newEmbed.fields = [];
  }

  let found = false;
  for (const f of newEmbed.fields) {
    if (typeof f.name === "string" && f.name.toLowerCase().includes("status")) {
      f.value = "🔴 **Disconnected**";
      f.inline = true;
      found = true;
      break;
    }
  }
  if (!found) {
    newEmbed.fields.push({
      name: "Status",
      value: "🔴 **Disconnected**",
      inline: true,
    });
  }

  const payload = { embeds: [newEmbed] };

  const url = `${webhookUrl}/messages/${messageId}`;

  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "Status-API",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    console.error("[Status] PATCH failed", res.status, text);
    throw new Error("PATCH failed");
  }
}

// ===== SESSIONS (RAM) =====
const sessions = new Map();

// POST /register
app.post("/register", async (req, res) => {
  try {
    const {
      sessionId,
      webhookUrl,   // WEBHOOK_URL từ script (vault URL hoặc webhook thật)
      messageId,
      channelId,
      username,
      displayName,
      placeId,
      jobId,
      embed,
    } = req.body || {};

    if (!sessionId || !webhookUrl || !messageId || !channelId) {
      return res.status(400).json({ error: "missing fields" });
    }

    sessions.set(sessionId, {
      sessionId,
      webhookKey: webhookUrl,   // giữ vault URL, sau này resolve trong patch
      messageId,
      channelId,
      username,
      displayName,
      placeId,
      jobId,
      embed,
      lastPing: Date.now(),
    });

    console.log("[Status] Registered session", sessionId);
    return res.json({ ok: true });
  } catch (err) {
    console.error("[Status] /register error", err);
    return res.status(500).json({ error: "internal" });
  }
});

// POST /ping
app.post("/ping", (req, res) => {
  try {
    const { sessionId } = req.body || {};
    if (!sessionId || !sessions.has(sessionId)) {
      return res.status(404).json({ error: "session not found" });
    }
    const s = sessions.get(sessionId);
    s.lastPing = Date.now();
    return res.json({ ok: true });
  } catch (err) {
    console.error("[Status] /ping error", err);
    return res.status(500).json({ error: "internal" });
  }
});

// Timer: check timeout
setInterval(async () => {
  const now = Date.now();
  for (const [sessionId, s] of sessions.entries()) {
    if (now - s.lastPing > HEARTBEAT_TIMEOUT_MS) {
      console.log("[Status] Session timeout:", sessionId);
      try {
        await patchMessageDisconnected(
          s.webhookKey,
          s.messageId,
          s.channelId,
          s.embed
        );
      } catch (err) {
        console.error("[Status] patch disconnected failed:", err);
      }
      sessions.delete(sessionId);
    }
  }
}, 5000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Status API listening on port", PORT);
});
