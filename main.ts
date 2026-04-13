const TIKTOK_CLIENT_KEY = Deno.env.get("TIKTOK_CLIENT_KEY") ?? "";
const TIKTOK_CLIENT_SECRET = Deno.env.get("TIKTOK_CLIENT_SECRET") ?? "";
const BASE_URL = Deno.env.get("BASE_URL") ?? "http://localhost:8000";

const TIKTOK_AUTH_URL = "https://www.tiktok.com/v2/auth/authorize";
const TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/";
const TIKTOK_USER_URL = "https://open.tiktokapis.com/v2/user/info/";
const REDIRECT_PATH = "/auth/tiktok/callback";

// In-memory stores (MVP only — not persistent across deploys)
const sessions = new Map<string, { user: TikTokUser; accessToken: string }>();
const pkceStore = new Map<string, string>(); // state -> code_verifier

interface TikTokUser {
  open_id: string;
  union_id?: string;
  avatar_url?: string;
  display_name?: string;
  username?: string;
}

function generateId(): string {
  return crypto.randomUUID();
}

function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  // URL-safe base64 (no padding) — valid verifier per RFC 7636
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function computeCodeChallenge(verifier: string): Promise<string> {
  const encoded = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  // TikTok expects hex-encoded SHA-256 (not base64url)
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getSessionId(req: Request): string | null {
  const cookie = req.headers.get("cookie") ?? "";
  const match = cookie.match(/session_id=([^;]+)/);
  return match ? match[1] : null;
}

function setSessionCookie(sessionId: string): string {
  return `session_id=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;
}

function clearSessionCookie(): string {
  return "session_id=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
}

// ── HTML rendering ──────────────────────────────────────────────────────────

function renderPage(body: string): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TikTok OAuth MVP</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #f5f5f5;
      color: #333;
    }
    .card {
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 2px 16px rgba(0,0,0,0.08);
      padding: 2.5rem;
      max-width: 420px;
      width: 100%;
      text-align: center;
    }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; }
    .avatar {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      margin: 0 auto 1rem;
      display: block;
    }
    .username { color: #888; font-size: 0.9rem; margin-bottom: 0.25rem; }
    .display-name { font-size: 1.25rem; font-weight: 600; margin-bottom: 0.25rem; }
    .open-id { color: #aaa; font-size: 0.75rem; word-break: break-all; margin-bottom: 1.5rem; }
    .btn {
      display: inline-block;
      padding: 0.75rem 2rem;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 1rem;
      cursor: pointer;
      border: none;
      transition: opacity 0.15s;
    }
    .btn:hover { opacity: 0.85; }
    .btn-tiktok { background: #000; color: #fff; }
    .btn-logout { background: #e0e0e0; color: #333; margin-top: 1rem; }
    .error { color: #c00; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="card">${body}</div>
</body>
</html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function homePage(): Response {
  return renderPage(`
    <h1>TikTok OAuth MVP</h1>
    <a class="btn btn-tiktok" href="/auth/tiktok">Sign in with TikTok</a>
  `);
}

function userPage(user: TikTokUser): Response {
  const avatar = user.avatar_url
    ? `<img class="avatar" src="${user.avatar_url}" alt="avatar" />`
    : "";
  const displayName = user.display_name ?? "Unknown";
  const username = user.username ? `@${user.username}` : "";
  return renderPage(`
    <h1>Welcome!</h1>
    ${avatar}
    <div class="display-name">${displayName}</div>
    ${username ? `<div class="username">${username}</div>` : ""}
    <div class="open-id">ID: ${user.open_id}</div>
    <a class="btn btn-logout" href="/logout">Sign out</a>
  `);
}

function errorPage(message: string): Response {
  return renderPage(`
    <h1>Something went wrong</h1>
    <p class="error">${message}</p>
    <a class="btn btn-tiktok" href="/">Try again</a>
  `);
}

// ── OAuth helpers ───────────────────────────────────────────────────────────

async function exchangeCode(code: string, codeVerifier: string): Promise<{ accessToken: string; openId: string }> {
  const body = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    client_secret: TIKTOK_CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: `${BASE_URL}${REDIRECT_PATH}`,
    code_verifier: codeVerifier,
  });

  const res = await fetch(TIKTOK_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const json = await res.json();
  console.dir({ tokenResponse: json }, { depth: null });

  if (!json.access_token) {
    throw new Error(json.error_description ?? json.message ?? "Token exchange failed");
  }

  return { accessToken: json.access_token, openId: json.open_id };
}

async function fetchUser(accessToken: string): Promise<TikTokUser> {
  const fields = "open_id,union_id,avatar_url,display_name,username";
  const url = `${TIKTOK_USER_URL}?fields=${fields}`;

  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const json = await res.json();
  console.dir({ userResponse: json }, { depth: null });

  if (json.error?.code !== "ok" && json.error?.code !== undefined) {
    throw new Error(json.error?.message ?? "Failed to fetch user info");
  }

  return json.data.user as TikTokUser;
}

// ── Route handlers ──────────────────────────────────────────────────────────

async function handleAuthStart(): Promise<Response> {
  const state = generateId();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await computeCodeChallenge(codeVerifier);

  // Store verifier keyed by state so we can retrieve it in the callback
  pkceStore.set(state, codeVerifier);

  const params = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    response_type: "code",
    scope: "user.info.basic,user.info.profile",
    redirect_uri: `${BASE_URL}${REDIRECT_PATH}`,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  return new Response(null, {
    status: 302,
    headers: {
      location: `${TIKTOK_AUTH_URL}?${params}`,
      "set-cookie": `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`,
    },
  });
}

async function handleCallback(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    const desc = url.searchParams.get("error_description") ?? error;
    return errorPage(desc);
  }

  if (!code) {
    return errorPage("No authorization code received.");
  }

  // Retrieve and consume the PKCE code_verifier
  const codeVerifier = state ? pkceStore.get(state) : undefined;
  if (state) pkceStore.delete(state);
  if (!codeVerifier) {
    return errorPage("Missing PKCE code verifier — session may have expired. Please try again.");
  }

  try {
    const { accessToken } = await exchangeCode(code, codeVerifier);
    const user = await fetchUser(accessToken);

    console.dir({ authenticatedUser: user }, { depth: null });

    const sessionId = generateId();
    sessions.set(sessionId, { user, accessToken });

    const page = userPage(user);
    page.headers.set("set-cookie", setSessionCookie(sessionId));
    return page;
  } catch (err) {
    console.error("OAuth callback error:", err);
    return errorPage(err instanceof Error ? err.message : "Authentication failed.");
  }
}

function handleLogout(req: Request): Response {
  const sessionId = getSessionId(req);
  if (sessionId) sessions.delete(sessionId);

  return new Response(null, {
    status: 302,
    headers: {
      location: "/",
      "set-cookie": clearSessionCookie(),
    },
  });
}

// ── Server ──────────────────────────────────────────────────────────────────

Deno.serve({ port: 8000 }, async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  const path = url.pathname;

  if (path === "/auth/tiktok") return await handleAuthStart();
  if (path === REDIRECT_PATH) return await handleCallback(req);
  if (path === "/logout") return handleLogout(req);

  // Home — show user page if session exists, otherwise sign-in
  if (path === "/") {
    const sessionId = getSessionId(req);
    const session = sessionId ? sessions.get(sessionId) : null;
    if (session) return userPage(session.user);
    return homePage();
  }

  return new Response("Not found", { status: 404 });
});
