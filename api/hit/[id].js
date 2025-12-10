// api/hit/[id].js
const crypto = require("crypto");

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ENCRYPTION_KEY,
} = process.env;

function getKey() {
  const base = ENCRYPTION_KEY || "CHANGE_THIS_TO_A_LONG_SECRET";
  return crypto.createHash("sha256").update(String(base)).digest();
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

// ========= Rate limit đơn giản (in-memory) =========
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

// ============================================

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const { id, ...queryRest } = req.query || {};
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

  if (!checkIp(ip)) {
    res.status(429).json({ error: "IP rate limit exceeded" });
    return;
  }
  if (!checkId(id)) {
    res.status(429).json({ error: "Webhook rate limit exceeded" });
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

    // ---- GHÉP query (?wait=true, ...) sang Discord webhook ----
    let targetUrl = webhookUrl;
    const qs = new URLSearchParams(queryRest || {});
    const qsStr = qs.toString();
    if (qsStr) {
      targetUrl += (webhookUrl.includes("?") ? "&" : "?") + qsStr;
    }

    // Forward tới Discord
    const discordResp = await fetch(targetUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: rawBody,
    });

    const text = await discordResp.text(); // nếu có JSON (wait=true) thì ở đây là JSON string

    res
      .status(discordResp.status)
      .json({ status: discordResp.status, response: text });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
};
