// Cloudflare Worker — Plugin Upload API
// Bindings: DB (D1), PLUGINS_BUCKET (R2)
// Secrets: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, VATSIM_CLIENT_ID, VATSIM_CLIENT_SECRET
// Vars: ADMIN_EMAIL, SITE_ORIGIN

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = env.SITE_ORIGIN;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    try {
      const path = url.pathname;

      // --- Google OAuth (Admin) ---
      if (path === "/auth/google") return googleRedirect(env, url);
      if (path === "/auth/google/callback") return googleCallback(request, env, url);

      // --- VATSIM OAuth (Uploaders) ---
      if (path === "/auth/vatsim") return vatsimRedirect(env, url);
      if (path === "/auth/vatsim/callback") return vatsimCallback(request, env, url);

      // --- Admin endpoints (require admin token) ---
      if (path === "/admin/users" && request.method === "GET") return adminListUsers(request, env, origin);
      if (path === "/admin/users" && request.method === "POST") return adminAddUser(request, env, origin);
      if (path === "/admin/users" && request.method === "DELETE") return adminRemoveUser(request, env, origin);

      // --- Upload endpoint ---
      if (path === "/upload" && request.method === "POST") return handleUpload(request, env, origin);

      // --- List plugins ---
      if (path === "/plugins" && request.method === "GET") return listPlugins(env, origin);

      return json({ error: "Not found" }, 404, origin);
    } catch (err) {
      return json({ error: "Internal server error" }, 500, origin);
    }
  },
};

// ──────────────────────────────────────
// Helpers
// ──────────────────────────────────────

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

// Create a signed token (HMAC-SHA256) using GOOGLE_CLIENT_SECRET as key
async function createToken(payload, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const data = JSON.stringify(payload);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const sigHex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
  return btoa(JSON.stringify({ data, sig: sigHex }));
}

async function verifyToken(token, secret) {
  try {
    const { data, sig } = JSON.parse(atob(token));
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sigBytes = new Uint8Array(sig.match(/.{2}/g).map(h => parseInt(h, 16)));
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(data));
    if (!valid) return null;
    const payload = JSON.parse(data);
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getBearer(request) {
  const auth = request.headers.get("Authorization") || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : null;
}

// ──────────────────────────────────────
// Google OAuth (Admin)
// ──────────────────────────────────────

function googleRedirect(env, url) {
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: `${url.origin}/auth/google/callback`,
    response_type: "code",
    scope: "openid email",
    state,
    prompt: "select_account",
  });
  return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
}

async function googleCallback(request, env, url) {
  const code = url.searchParams.get("code");
  if (!code) return redirectWithError(env, "/admin.html", "Missing code");

  // Exchange code for tokens
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${url.origin}/auth/google/callback`,
      grant_type: "authorization_code",
    }),
  });
  const tokens = await tokenRes.json();
  if (!tokens.id_token) return redirectWithError(env, "/admin.html", "Auth failed");

  // Decode JWT (we trust Google's token since we just fetched it)
  const claims = JSON.parse(atob(tokens.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  const email = claims.email;

  if (email !== env.ADMIN_EMAIL) {
    return redirectWithError(env, "/admin.html", "Unauthorized");
  }

  // Issue our own session token (24h)
  const token = await createToken(
    { role: "admin", email, exp: Date.now() + 86400000 },
    env.GOOGLE_CLIENT_SECRET
  );

  return Response.redirect(`${env.SITE_ORIGIN}/admin.html#token=${token}`, 302);
}

// ──────────────────────────────────────
// VATSIM OAuth (Uploaders)
// ──────────────────────────────────────

function vatsimRedirect(env, url) {
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: env.VATSIM_CLIENT_ID,
    redirect_uri: `${url.origin}/auth/vatsim/callback`,
    response_type: "code",
    scope: "full_name vatsim_details",
    state,
  });
  return Response.redirect(`https://auth.vatsim.net/oauth/authorize?${params}`, 302);
}

async function vatsimCallback(request, env, url) {
  const code = url.searchParams.get("code");
  if (!code) return redirectWithError(env, "/upload.html", "Missing code");

  // Exchange code
  const tokenRes = await fetch("https://auth.vatsim.net/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: env.VATSIM_CLIENT_ID,
      client_secret: env.VATSIM_CLIENT_SECRET,
      redirect_uri: `${url.origin}/auth/vatsim/callback`,
      code,
    }),
  });
  const tokens = await tokenRes.json();
  if (!tokens.access_token) return redirectWithError(env, "/upload.html", "Auth failed");

  // Get user info
  const userRes = await fetch("https://auth.vatsim.net/api/user", {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const user = await userRes.json();
  const cid = String(user.data.cid);
  const name = `${user.data.personal.name_first} ${user.data.personal.name_last}`;

  // Check if allowed
  const row = await env.DB.prepare("SELECT vatsim_cid FROM allowed_users WHERE vatsim_cid = ?").bind(cid).first();
  if (!row) return redirectWithError(env, "/upload.html", "Not authorized to upload");

  // Issue upload token (8h)
  const token = await createToken(
    { role: "uploader", cid, name, exp: Date.now() + 28800000 },
    env.GOOGLE_CLIENT_SECRET
  );

  return Response.redirect(`${env.SITE_ORIGIN}/upload.html#token=${token}`, 302);
}

function redirectWithError(env, page, message) {
  return Response.redirect(`${env.SITE_ORIGIN}${page}#error=${encodeURIComponent(message)}`, 302);
}

// ──────────────────────────────────────
// Admin: manage allowed users
// ──────────────────────────────────────

async function requireAdmin(request, env) {
  const token = getBearer(request);
  if (!token) return null;
  const payload = await verifyToken(token, env.GOOGLE_CLIENT_SECRET);
  if (!payload || payload.role !== "admin") return null;
  return payload;
}

async function adminListUsers(request, env, origin) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, origin);

  const { results } = await env.DB.prepare("SELECT * FROM allowed_users ORDER BY added_at DESC").all();
  return json({ users: results }, 200, origin);
}

async function adminAddUser(request, env, origin) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, origin);

  const { cid, name } = await request.json();
  if (!cid || !name) return json({ error: "cid and name required" }, 400, origin);

  const sanitizedCid = String(cid).replace(/[^0-9]/g, "");
  const sanitizedName = String(name).slice(0, 100);

  await env.DB.prepare("INSERT OR IGNORE INTO allowed_users (vatsim_cid, name) VALUES (?, ?)")
    .bind(sanitizedCid, sanitizedName).run();
  return json({ ok: true }, 200, origin);
}

async function adminRemoveUser(request, env, origin) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, origin);

  const { cid } = await request.json();
  if (!cid) return json({ error: "cid required" }, 400, origin);

  const sanitizedCid = String(cid).replace(/[^0-9]/g, "");
  await env.DB.prepare("DELETE FROM allowed_users WHERE vatsim_cid = ?").bind(sanitizedCid).run();
  return json({ ok: true }, 200, origin);
}

// ──────────────────────────────────────
// Upload
// ──────────────────────────────────────

async function handleUpload(request, env, origin) {
  const token = getBearer(request);
  if (!token) return json({ error: "Unauthorized" }, 401, origin);

  const payload = await verifyToken(token, env.GOOGLE_CLIENT_SECRET);
  if (!payload || payload.role !== "uploader") return json({ error: "Unauthorized" }, 401, origin);

  const formData = await request.formData();
  const file = formData.get("file");
  if (!file || !(file instanceof File)) return json({ error: "No file provided" }, 400, origin);

  // Validate file type
  const allowedExts = [".dll", ".xml", ".json", ".zip"];
  const ext = file.name.lastIndexOf(".") >= 0 ? file.name.slice(file.name.lastIndexOf(".")).toLowerCase() : "";
  if (!allowedExts.includes(ext)) {
    return json({ error: `File type not allowed. Allowed: ${allowedExts.join(", ")}` }, 400, origin);
  }

  // Max 50MB
  if (file.size > 50 * 1024 * 1024) {
    return json({ error: "File too large (max 50MB)" }, 400, origin);
  }

  // Sanitize filename: only allow alphanumeric, dash, underscore, dot
  const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, "_");
  const key = `${payload.cid}/${safeName}`;

  await env.PLUGINS_BUCKET.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" },
    customMetadata: { uploadedBy: payload.cid, uploaderName: payload.name },
  });

  return json({ ok: true, key }, 200, origin);
}

// ──────────────────────────────────────
// List plugins
// ──────────────────────────────────────

async function listPlugins(env, origin) {
  const listed = await env.PLUGINS_BUCKET.list({ limit: 1000 });
  const files = listed.objects.map(o => ({
    key: o.key,
    size: o.size,
    uploaded: o.uploaded,
  }));
  return json({ plugins: files }, 200, origin);
}
