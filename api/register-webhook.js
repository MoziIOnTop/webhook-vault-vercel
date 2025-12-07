// api/register-webhook.js
const crypto = require("crypto");

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ENCRYPTION_KEY,
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
}

function getKey() {
  const base = ENCRYPTION_KEY || "CHANGE_THIS_TO_A_LONG_SECRET";
  return crypto.createHash("sha256").update(String(base)).digest(); // 32 bytes
}

function encrypt(text) {
  const key = getKey();
  const iv = crypto.randomBytes(12); // 96-bit IV
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  // Parse body (Vercel đôi khi để string)
  let body = {};
  try {
    body =
      typeof req.body === "object" && req.body !== null
        ? req.body
        : JSON.parse(req.body || "{}");
  } catch {
    body = {};
  }

  const { owner_discord_id, webhook_url } = body;

  if (!owner_discord_id || !webhook_url) {
    res
      .status(400)
      .json({ error: "owner_discord_id and webhook_url are required" });
    return;
  }

  // Check webhook có phải Discord không
  try {
    const u = new URL(webhook_url);
    if (
      !/discord\.com$|discordapp\.com$/.test(u.hostname) ||
      !u.pathname.includes("/api/webhooks/")
    ) {
      res.status(400).json({ error: "Not a valid Discord webhook URL" });
      return;
    }
  } catch {
    res.status(400).json({ error: "Invalid URL" });
    return;
  }

  const id = "wh_" + crypto.randomBytes(9).toString("hex"); // publicId
  const webhook_enc = encrypt(webhook_url);

  try {
    const resp = await fetch(`${SUPABASE_URL}/rest/v1/webhooks`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({
        id,
        owner_discord_id: String(owner_discord_id),
        webhook_enc,
      }),
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      console.error("Supabase error register:", resp.status, data);
      res
        .status(500)
        .json({ error: "Supabase error", status: resp.status, data });
      return;
    }

    res.json({ id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Internal error" });
  }
};
