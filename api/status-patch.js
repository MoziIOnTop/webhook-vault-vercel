// api/status-patch.js
const crypto = require("crypto");

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ENCRYPTION_KEY,
  STATUS_SHARED_SECRET,
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

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  if (!STATUS_SHARED_SECRET) {
    res.status(500).json({ error: "STATUS_SHARED_SECRET not configured" });
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

  const ts = req.headers["x-status-timestamp"];
  const sig = req.headers["x-status-signature"];

  if (!ts || !sig) {
    res.status(401).json({ error: "missing signature" });
    return;
  }

  const payload = `${ts}.${JSON.stringify(body)}`;
  const expected = crypto
    .createHmac("sha256", STATUS_SHARED_SECRET)
    .update(payload)
    .digest("hex");

  try {
    if (
      !crypto.timingSafeEqual(
        Buffer.from(sig, "utf8"),
        Buffer.from(expected, "utf8")
      )
    ) {
      res.status(401).json({ error: "invalid signature" });
      return;
    }
  } catch {
    res.status(401).json({ error: "invalid signature" });
    return;
  }

  const { vault_id, message_id, embeds } = body;
  if (!vault_id || !message_id || !Array.isArray(embeds)) {
    res.status(400).json({ error: "missing fields" });
    return;
  }

  try {
    // lấy webhook_enc từ Supabase
    const url = `${SUPABASE_URL}/rest/v1/webhooks?id=eq.${encodeURIComponent(
      vault_id
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

    // PATCH message cũ
    const patchUrl = `${webhookUrl}/messages/${encodeURIComponent(
      message_id
    )}`;

    const patchResp = await fetch(patchUrl, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ embeds }),
    });

    const text = await patchResp.text();

    if (!patchResp.ok) {
      console.error(
        "[status-patch] Discord PATCH failed",
        patchResp.status,
        text
      );
      res
        .status(patchResp.status)
        .json({ error: "discord patch failed", response: text });
      return;
    }

    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }

    res.status(200).json({ ok: true, discord: json });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
};
