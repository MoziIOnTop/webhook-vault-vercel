// api/status-patch.js
// Nhận yêu cầu từ Status API để sửa message -> Disconnected
// PATCH qua Discord nhưng webhook thật luôn nằm trong vault (Supabase)

const crypto = require("crypto");

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ENCRYPTION_KEY,
  STATUS_SHARED_SECRET,
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("[status-patch] Missing SUPABASE_URL or SERVICE_ROLE_KEY");
}

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

// ---- verify HMAC từ Status API ----
function verifySignature(ts, rawBody, sig) {
  if (!STATUS_SHARED_SECRET) return false;
  try {
    const payload = `${ts}.${rawBody}`;
    const expected = crypto
      .createHmac("sha256", STATUS_SHARED_SECRET)
      .update(payload)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(sig, "hex"),
      Buffer.from(expected, "hex")
    );
  } catch {
    return false;
  }
}

module.exports = async (req, res) => {
  if (req.method !== "POST" && req.method !== "PATCH") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  if (!STATUS_SHARED_SECRET) {
    res.status(500).json({ error: "STATUS_SHARED_SECRET not set" });
    return;
  }

  // đọc body & stringify lại để tính HMAC
  let body = {};
  try {
    body =
      typeof req.body === "object" && req.body !== null
        ? req.body
        : JSON.parse(req.body || "{}");
  } catch {
    body = {};
  }
  const rawBody = JSON.stringify(body || {});

  const ts = req.headers["x-status-timestamp"];
  const sig = req.headers["x-status-signature"];

  if (!ts || !sig || !verifySignature(ts, rawBody, sig)) {
    res.status(401).json({ error: "invalid signature" });
    return;
  }

  const vaultId = body.vault_id || body.vaultId;
  const messageId = body.message_id || body.messageId;
  const embeds = body.embeds;

  if (!vaultId || !messageId || !Array.isArray(embeds)) {
    res.status(400).json({ error: "vault_id, message_id, embeds required" });
    return;
  }

  // body size guard (optional)
  if (Buffer.byteLength(rawBody, "utf8") > 4000) {
    res.status(413).json({ error: "Payload too large" });
    return;
  }

  try {
    // Lấy webhook_enc từ Supabase (giống file hit/[id].js)
    const url = `${SUPABASE_URL}/rest/v1/webhooks?id=eq.${encodeURIComponent(
      vaultId
    )}&select=webhook_enc`;

    const resp = await fetch(url, {
      method: "GET",
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
    });

    const rows = (await resp.json().catch(() => [])) || [];

    if (!resp.ok || !Array.isArray(rows) || rows.length === 0) {
      res.status(404).json({ error: "Unknown webhook id" });
      return;
    }

    const webhookUrl = decrypt(rows[0].webhook_enc);

    // PATCH message trên Discord
    const discordResp = await fetch(
      `${webhookUrl}/messages/${encodeURIComponent(messageId)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ embeds }),
      }
    );

    const text = await discordResp.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }

    res.status(discordResp.status).json(json);
  } catch (e) {
    console.error("[status-patch] error", e);
    res.status(500).json({ error: "Internal error" });
  }
};
