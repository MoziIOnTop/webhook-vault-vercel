// api/hit/[id].js
const crypto = require("crypto");

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ENCRYPTION_KEY,
} = process.env;

function getKey() {
  const base = ENCRYPTION_KEY || "CHANGE_THIS_TO_A_LONG_SECRET";
  return crypto.createHash("sha256").update(String(base)).digest(); // 32 bytes
}

function decrypt(b64) {
  const key = getKey();
  const buf = Buffer.from(b64, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString("utf8");
}

// ========= Rate limit cũ (tổng request) =========
const ipHits = new Map(); // ip -> [timestamps]
const idHits = new Map(); // id -> [timestamps]

function clean(arr, now, windowSec) {
  return arr.filter((t) => now - t < windowSec);
}

function checkIp(ip) {
  const now = Date.now() / 1000;
  const arr = clean(ipHits.get(ip) || [], now, 3600);
  arr.push(now);
  ipHits.set(ip, arr);

  const last1s = arr.filter((t) => now - t < 1).length;
  const last60s = arr.filter((t) => now - t < 60).length;
  const last3600 = arr.length;

  if (last1s > 5 || last60s > 40 || last3600 > 500) return false;
  return true;
}

function checkId(id) {
  const now = Date.now() / 1000;
  const arr = clean(idHits.get(id) || [], now, 3600);
  arr.push(now);
  idHits.set(id, arr);

  const last60s = arr.filter((t) => now - t < 60).length;
  const last3600 = arr.length;

  if (last60s > 120 || last3600 > 2000) return false;
  return true;
}

// ========= Anti-SPAM theo IP (@everyone + trùng content) =========

// Đếm @everyone theo IP
// ip -> [timestamps] (chỉ cho các message có @everyone)
const ipEveryoneHits = new Map();

// Đếm content trùng theo IP
// ip -> Map<normalizedText, [timestamps]>
const ipContentHits = new Map();

// gom toàn bộ text từ content + embeds để check
function extractAllText(body) {
  const parts = [];
  if (body && typeof body.content === "string") {
    parts.push(body.content);
  }
  const embeds = Array.isArray(body?.embeds) ? body.embeds : [];
  for (const e of embeds) {
    if (!e || typeof e !== "object") continue;
    if (typeof e.title === "string") parts.push(e.title);
    if (typeof e.description === "string") parts.push(e.description);
    const fields = Array.isArray(e.fields) ? e.fields : [];
    for (const f of fields) {
      if (!f || typeof f !== "object") continue;
      if (typeof f.name === "string") parts.push(f.name);
      if (typeof f.value === "string") parts.push(f.value);
    }
  }
  return parts.join("\n");
}

// Kiểm tra rule:
// - 3 lần / phút hoặc 20 lần / ngày cho:
//   + message có @everyone
//   + message có cùng content (tính trên full text content + embeds)
function checkAntiSpam(ip, body) {
  const now = Date.now() / 1000;
  const text = extractAllText(body);
  const normalized = text.trim().toLowerCase();

  // 1) Rule @everyone
  if (/@everyone/i.test(text)) {
    let arr = clean(ipEveryoneHits.get(ip) || [], now, 86400);
    arr.push(now);
    ipEveryoneHits.set(ip, arr);

    const last1m = arr.filter((t) => now - t < 60).length;
    const last1d = arr.length;

    if (last1m > 3 || last1d > 20) {
      return {
        ok: false,
        reason: "too many @everyone from this IP",
      };
    }
  }

  // 2) Rule content trùng (kể cả text trong embed)
  if (normalized.length > 0) {
    let map = ipContentHits.get(ip);
    if (!map) {
      map = new Map();
      ipContentHits.set(ip, map);
    }
    let arr = clean(map.get(normalized) || [], now, 86400);
    arr.push(now);
    map.set(normalized, arr);

    const last1m = arr.filter((t) => now - t < 60).length;
    const last1d = arr.length;

    if (last1m > 3 || last1d > 20) {
      return {
        ok: false,
        reason: "too many identical messages from this IP",
      };
    }
  }

  // pass
  return { ok: true };
}

// ============================================

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const { id, wait } = req.query;
  if (!id) {
    res.status(400).json({ error: "Missing id" });
    return;
  }

  let body = {};
  try {
    body =
      typeof req.body === "object" && req.body !== null
        ? req.body
        : JSON.parse(req.body || "{}");
  } catch {
    body = {};
  }

  const ip =
    (req.headers["x-forwarded-for"] || "")
      .split(",")[0]
      .trim() ||
    req.socket?.remoteAddress ||
    "unknown";

  // Rate limit tổng
  if (!checkIp(ip)) {
    res.status(429).json({ error: "IP rate limit exceeded" });
    return;
  }
  if (!checkId(id)) {
    res.status(429).json({ error: "Webhook rate limit exceeded" });
    return;
  }

  // Anti-SPAM riêng (everyone + trùng content)
  const spamCheck = checkAntiSpam(ip, body);
  if (!spamCheck.ok) {
    res.status(429).json({
      error: "Anti-spam limit",
      reason: spamCheck.reason,
    });
    return;
  }

  // body size guard
  const rawBody = JSON.stringify(body || {});
  if (Buffer.byteLength(rawBody, "utf8") > 4000) {
    res.status(413).json({ error: "Payload too large" });
    return;
  }

  try {
    // Lấy webhook_enc từ Supabase
    const url = `${SUPABASE_URL}/rest/v1/webhooks?id=eq.${encodeURIComponent(
      id
    )}&select=webhook_enc`;

    const resp = await fetch(url, {
      method: "GET",
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
    });

    const rows = await resp.json().catch(() => []);

    if (!resp.ok || !Array.isArray(rows) || rows.length === 0) {
      res.status(404).json({ error: "Unknown webhook id" });
      return;
    }

    const webhookUrl = decrypt(rows[0].webhook_enc);

    // Mặc định dùng ?wait=true để lấy message id
    let useWait = true;
    if (typeof wait !== "undefined") {
      useWait = String(wait).toLowerCase() === "true";
    }

    let targetUrl = webhookUrl;
    if (useWait) {
      const sep = webhookUrl.includes("?") ? "&" : "?";
      targetUrl = `${webhookUrl}${sep}wait=true`;
    }

    // Forward tới Discord
    const discordResp = await fetch(targetUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: rawBody,
    });

    const text = await discordResp.text();

    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }

    res.status(discordResp.status).json(json);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
};
