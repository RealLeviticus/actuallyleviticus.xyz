// Cloudflare Worker — Plugin Upload API
// Bindings: DB (D1), PLUGINS_BUCKET (R2)
// Secrets: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, VATSIM_CLIENT_ID, VATSIM_CLIENT_SECRET, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET
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

      // --- Discord OAuth (Uploaders) ---
      if (path === "/auth/discord") return discordRedirect(env, url);
      if (path === "/auth/discord/callback") return discordCallback(request, env, url);

      // --- Admin endpoints (require admin token) ---
      if (path === "/admin/users" && request.method === "GET") return adminListUsers(request, env, origin);
      if (path === "/admin/users" && request.method === "POST") return adminAddUser(request, env, origin);
      if (path === "/admin/users" && request.method === "PUT") return adminEditUser(request, env, origin);
      if (path === "/admin/users" && request.method === "DELETE") return adminRemoveUser(request, env, origin);

      // --- Upload endpoint ---
      if (path === "/upload" && request.method === "POST") return handleUpload(request, env, origin);
      if (path === "/upload/banner" && request.method === "POST") return handleBannerUpload(request, env, origin);
      if (path === "/upload/banner" && request.method === "GET") return getBanner(request, env, origin);

      // --- Plugin management ---
      if (path === "/my-plugins" && request.method === "GET") return getMyPlugins(request, env, origin);
      if (path.startsWith("/plugins/") && request.method === "PUT") return updatePlugin(request, env, origin, path);
      if (path.startsWith("/plugins/") && request.method === "DELETE") return deletePlugin(request, env, origin, path);

      // --- Latest installer ---
      if (path === "/latest-installer" && request.method === "GET") return latestInstaller(env, origin);

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
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
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

  // Check if allowed by vatsim_cid
  const row = await env.DB.prepare("SELECT id, name FROM allowed_users WHERE vatsim_cid = ?").bind(cid).first();
  if (!row) return redirectWithError(env, "/upload.html", "Not authorized to upload");

  // Issue upload token (8h) — use DB id so plugins are tied to the person
  const token = await createToken(
    { role: "uploader", id: String(row.id), name: row.name, authType: "vatsim", exp: Date.now() + 28800000 },
    env.GOOGLE_CLIENT_SECRET
  );

  return Response.redirect(`${env.SITE_ORIGIN}/upload.html#token=${token}`, 302);
}

// ──────────────────────────────────────
// Discord OAuth (Uploaders)
// ──────────────────────────────────────

function discordRedirect(env, url) {
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    redirect_uri: `${url.origin}/auth/discord/callback`,
    response_type: "code",
    scope: "identify",
    state,
    prompt: "consent",
  });
  return Response.redirect(`https://discord.com/oauth2/authorize?${params}`, 302);
}

async function discordCallback(request, env, url) {
  const code = url.searchParams.get("code");
  if (!code) return redirectWithError(env, "/upload.html", "Missing code");

  // Exchange code for token
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      redirect_uri: `${url.origin}/auth/discord/callback`,
      code,
    }),
  });
  const tokens = await tokenRes.json();
  if (!tokens.access_token) return redirectWithError(env, "/upload.html", "Auth failed");

  // Get user info
  const userRes = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const user = await userRes.json();
  const discordId = String(user.id);
  const name = user.global_name || user.username;
  const avatarHash = user.avatar;
  const avatarUrl = avatarHash
    ? `https://cdn.discordapp.com/avatars/${discordId}/${avatarHash}.png?size=128`
    : null;

  // Check if allowed by discord_id
  const row = await env.DB.prepare("SELECT id, name FROM allowed_users WHERE discord_id = ?").bind(discordId).first();
  if (!row) return redirectWithError(env, "/upload.html", "Not authorized to upload");

  // Update avatar on login
  if (avatarUrl) {
    await env.DB.prepare("UPDATE allowed_users SET avatar_url = ? WHERE id = ?").bind(avatarUrl, row.id).run();
  }

  // Issue upload token (8h) — use DB id so plugins are tied to the person
  const token = await createToken(
    { role: "uploader", id: String(row.id), name: row.name, authType: "discord", exp: Date.now() + 28800000 },
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

  const { name, vatsimCid, discordId } = await request.json();
  if (!name) return json({ error: "Name is required" }, 400, origin);
  if (!vatsimCid && !discordId) return json({ error: "At least one ID (VATSIM CID or Discord ID) is required" }, 400, origin);

  const sanitizedName = String(name).slice(0, 100);
  const sanitizedVatsim = vatsimCid ? String(vatsimCid).replace(/[^0-9]/g, "") || null : null;
  const sanitizedDiscord = discordId ? String(discordId).replace(/[^0-9]/g, "") || null : null;

  // Fetch Discord avatar if discord ID provided
  let avatarUrl = null;
  if (sanitizedDiscord) {
    try {
      const res = await fetch(`https://discord.com/api/v10/users/${sanitizedDiscord}`, {
        headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN || ""}` },
      });
      if (res.ok) {
        const u = await res.json();
        if (u.avatar) avatarUrl = `https://cdn.discordapp.com/avatars/${sanitizedDiscord}/${u.avatar}.png?size=128`;
      }
    } catch {}
  }

  await env.DB.prepare(
    "INSERT INTO allowed_users (name, vatsim_cid, discord_id, avatar_url) VALUES (?, ?, ?, ?)"
  ).bind(sanitizedName, sanitizedVatsim, sanitizedDiscord, avatarUrl).run();

  return json({ ok: true }, 200, origin);
}

async function adminEditUser(request, env, origin) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, origin);

  const { id, name, vatsimCid, discordId } = await request.json();
  if (!id) return json({ error: "User id required" }, 400, origin);

  const existing = await env.DB.prepare("SELECT * FROM allowed_users WHERE id = ?").bind(id).first();
  if (!existing) return json({ error: "User not found" }, 404, origin);

  const newName = name ? String(name).slice(0, 100) : existing.name;
  const newVatsim = vatsimCid !== undefined ? (vatsimCid ? String(vatsimCid).replace(/[^0-9]/g, "") || null : null) : existing.vatsim_cid;
  const newDiscord = discordId !== undefined ? (discordId ? String(discordId).replace(/[^0-9]/g, "") || null : null) : existing.discord_id;

  // Fetch Discord avatar if discord ID is being set/changed
  let avatarUrl = existing.avatar_url;
  if (newDiscord && newDiscord !== existing.discord_id) {
    try {
      const res = await fetch(`https://discord.com/api/v10/users/${newDiscord}`, {
        headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN || ""}` },
      });
      if (res.ok) {
        const u = await res.json();
        avatarUrl = u.avatar ? `https://cdn.discordapp.com/avatars/${newDiscord}/${u.avatar}.png?size=128` : null;
      }
    } catch {}
  } else if (!newDiscord) {
    avatarUrl = null;
  }

  await env.DB.prepare(
    "UPDATE allowed_users SET name = ?, vatsim_cid = ?, discord_id = ?, avatar_url = ? WHERE id = ?"
  ).bind(newName, newVatsim, newDiscord, avatarUrl, id).run();

  return json({ ok: true }, 200, origin);
}

async function adminRemoveUser(request, env, origin) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, origin);

  const { id } = await request.json();
  if (!id) return json({ error: "id required" }, 400, origin);

  await env.DB.prepare("DELETE FROM allowed_users WHERE id = ?").bind(id).run();
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
  const pluginName = formData.get("pluginName");
  if (!file || !(file instanceof File)) return json({ error: "No file provided" }, 400, origin);
  if (!pluginName) return json({ error: "Plugin name is required" }, 400, origin);

  // Sanitize plugin name: only allow alphanumeric, dash, underscore
  const safeFolderName = String(pluginName).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100);
  if (!safeFolderName) return json({ error: "Invalid plugin name" }, 400, origin);

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

  // Sanitize filename
  const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, "_");
  const key = `${safeFolderName}/${safeName}`;

  await env.PLUGINS_BUCKET.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" },
    customMetadata: { uploadedBy: payload.id, uploaderName: payload.name },
  });

  // Upsert plugin record in D1
  await env.DB.prepare(`
    INSERT INTO plugins (name, display_name, uploader_id, uploader_name)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET updated_at = datetime('now')
  `).bind(safeFolderName, pluginName, payload.id, payload.name).run();

  return json({ ok: true, key }, 200, origin);
}

// ──────────────────────────────────────
// Banner upload
// ──────────────────────────────────────

async function handleBannerUpload(request, env, origin) {
  const token = getBearer(request);
  if (!token) return json({ error: "Unauthorized" }, 401, origin);

  const payload = await verifyToken(token, env.GOOGLE_CLIENT_SECRET);
  if (!payload || payload.role !== "uploader") return json({ error: "Unauthorized" }, 401, origin);

  const formData = await request.formData();
  const file = formData.get("banner");
  const pluginName = formData.get("pluginName");
  if (!file || !(file instanceof File)) return json({ error: "No banner file provided" }, 400, origin);
  if (!pluginName) return json({ error: "Plugin name is required" }, 400, origin);

  const safeFolderName = String(pluginName).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100);
  if (!safeFolderName) return json({ error: "Invalid plugin name" }, 400, origin);

  // Validate image type
  const allowedExts = [".png", ".jpg", ".jpeg", ".webp"];
  const ext = file.name.lastIndexOf(".") >= 0 ? file.name.slice(file.name.lastIndexOf(".")).toLowerCase() : "";
  if (!allowedExts.includes(ext)) {
    return json({ error: `Banner must be an image (${allowedExts.join(", ")})` }, 400, origin);
  }

  // Max 5MB for banners
  if (file.size > 5 * 1024 * 1024) {
    return json({ error: "Banner too large (max 5MB)" }, 400, origin);
  }

  const key = `${safeFolderName}/Banner/banner${ext}`;

  await env.PLUGINS_BUCKET.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || "image/png" },
    customMetadata: { uploadedBy: payload.id, uploaderName: payload.name },
  });

  return json({ ok: true, key }, 200, origin);
}

async function getBanner(request, env, origin) {
  const url = new URL(request.url);
  const pluginName = url.searchParams.get("plugin");
  if (!pluginName) return json({ error: "plugin name required" }, 400, origin);

  const safeName = String(pluginName).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100);
  const listed = await env.PLUGINS_BUCKET.list({ prefix: `${safeName}/Banner/` });

  if (!listed.objects.length) {
    return json({ banner: null }, 200, origin);
  }

  const banner = listed.objects[0];
  return json({ banner: { key: banner.key, size: banner.size } }, 200, origin);
}

// ──────────────────────────────────────
// Plugin management (for uploaders)
// ──────────────────────────────────────

async function requireUploader(request, env) {
  const token = getBearer(request);
  if (!token) return null;
  const payload = await verifyToken(token, env.GOOGLE_CLIENT_SECRET);
  if (!payload || payload.role !== "uploader") return null;
  return payload;
}

async function getMyPlugins(request, env, origin) {
  const user = await requireUploader(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, origin);

  const { results } = await env.DB.prepare(
    "SELECT * FROM plugins WHERE uploader_id = ? ORDER BY updated_at DESC"
  ).bind(user.id).all();

  // Enrich with file info from R2
  const enriched = await Promise.all(results.map(async (plugin) => {
    const listed = await env.PLUGINS_BUCKET.list({ prefix: `${plugin.name}/` });
    const files = listed.objects
      .filter(o => !o.key.includes("/Banner/"))
      .map(o => ({ key: o.key, size: o.size, uploaded: o.uploaded }));
    const bannerObj = listed.objects.find(o => o.key.includes("/Banner/"));
    return {
      ...plugin,
      files,
      banner: bannerObj ? bannerObj.key : null,
    };
  }));

  return json({ plugins: enriched }, 200, origin);
}

async function updatePlugin(request, env, origin, path) {
  const user = await requireUploader(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, origin);

  // /plugins/<encoded-name>
  const pluginName = decodeURIComponent(path.replace("/plugins/", ""));
  const safeName = pluginName.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100);

  // Check ownership
  const plugin = await env.DB.prepare(
    "SELECT * FROM plugins WHERE name = ? AND uploader_id = ?"
  ).bind(safeName, user.id).first();
  if (!plugin) return json({ error: "Plugin not found or not yours" }, 404, origin);

  const body = await request.json();
  const updates = [];
  const binds = [];

  if (body.displayName !== undefined) {
    updates.push("display_name = ?");
    binds.push(String(body.displayName).slice(0, 100));
  }
  if (body.description !== undefined) {
    updates.push("description = ?");
    binds.push(String(body.description).slice(0, 500));
  }
  if (body.version !== undefined) {
    updates.push("version = ?");
    binds.push(String(body.version).replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 30));
  }
  if (body.isDev !== undefined) {
    updates.push("is_dev = ?");
    binds.push(body.isDev ? 1 : 0);
  }

  if (!updates.length) return json({ error: "Nothing to update" }, 400, origin);

  updates.push("updated_at = datetime('now')");
  binds.push(safeName, user.id);

  await env.DB.prepare(
    `UPDATE plugins SET ${updates.join(", ")} WHERE name = ? AND uploader_id = ?`
  ).bind(...binds).run();

  return json({ ok: true }, 200, origin);
}

async function deletePlugin(request, env, origin, path) {
  const user = await requireUploader(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401, origin);

  const pluginName = decodeURIComponent(path.replace("/plugins/", ""));
  const safeName = pluginName.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100);

  // Check ownership
  const plugin = await env.DB.prepare(
    "SELECT * FROM plugins WHERE name = ? AND uploader_id = ?"
  ).bind(safeName, user.id).first();
  if (!plugin) return json({ error: "Plugin not found or not yours" }, 404, origin);

  // Delete all files from R2
  const listed = await env.PLUGINS_BUCKET.list({ prefix: `${safeName}/` });
  if (listed.objects.length) {
    await env.PLUGINS_BUCKET.delete(listed.objects.map(o => o.key));
  }

  // Delete from D1
  await env.DB.prepare("DELETE FROM plugins WHERE name = ? AND uploader_id = ?")
    .bind(safeName, user.id).run();

  return json({ ok: true }, 200, origin);
}

// ──────────────────────────────────────
// Latest installer
// ──────────────────────────────────────

async function latestInstaller(env, origin) {
  // The installer bucket is cdn.actuallyleviticus.xyz (a separate public R2 bucket).
  // We resolve the latest by listing the InstallerUpdates/ prefix in the plugins bucket
  // OR — more reliably — by parsing known CDN listing via the public URL pattern.
  // Since we don't have a binding to the CDN bucket, we fetch the public CDN directory
  // and parse installer filenames to find the highest semver.
  const PREFIX = "InstallerUpdates/vatSys%20Plugin%20Installer%20Setup%20";
  const CDN = "https://cdn.actuallyleviticus.xyz/";

  // Probe versions server-side (no CORS issue from Worker)
  const versions = [];
  for (let major = 1; major <= 3; major++)
    for (let minor = 0; minor <= 9; minor++)
      for (let patch = 0; patch <= 30; patch++)
        versions.push({ major, minor, patch });

  const results = await Promise.allSettled(
    versions.map(async ({ major, minor, patch }) => {
      const ver = `${major}.${minor}.${patch}`;
      const res = await fetch(
        `${CDN}InstallerUpdates/vatSys%20Plugin%20Installer%20Setup%20${ver}.exe`,
        { method: "HEAD" }
      );
      if (!res.ok) throw new Error();
      return { major, minor, patch, ver };
    })
  );

  const found = results
    .filter(r => r.status === "fulfilled")
    .map(r => r.value)
    .sort((a, b) => (a.major - b.major) || (a.minor - b.minor) || (a.patch - b.patch));

  if (!found.length) {
    return json({ error: "No installer found" }, 404, origin);
  }

  const latest = found[found.length - 1];
  const url = `${CDN}InstallerUpdates/vatSys%20Plugin%20Installer%20Setup%20${latest.ver}.exe`;

  return new Response(JSON.stringify({ version: latest.ver, url }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300", // Cache at edge for 5 min
      ...corsHeaders(origin),
    },
  });
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
