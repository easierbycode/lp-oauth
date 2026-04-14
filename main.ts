const TIKTOK_CLIENT_KEY = Deno.env.get("TIKTOK_CLIENT_KEY") ?? "";
const TIKTOK_CLIENT_SECRET = Deno.env.get("TIKTOK_CLIENT_SECRET") ?? "";
const BASE_URL = Deno.env.get("BASE_URL") ?? "http://localhost:8000";

const TIKTOK_AUTH_URL = "https://www.tiktok.com/v2/auth/authorize";
const TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/";
const TIKTOK_USER_URL = "https://open.tiktokapis.com/v2/user/info/";
const TIKTOK_VIDEO_LIST_URL = "https://open.tiktokapis.com/v2/video/list/";
const REDIRECT_PATH = "/auth/tiktok/callback";
const WEBHOOK_PATH = "/webhooks/tiktok";

// Reject webhook payloads whose signed timestamp is older than this, to mitigate
// replay attacks. TikTok's recommended tolerance is on the order of minutes.
const WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS = 5 * 60;

// Fields returned from user/info/, grouped by required scope.
const USER_FIELDS = [
  // user.info.basic
  "open_id",
  "union_id",
  "avatar_url",
  "avatar_url_100",
  "avatar_large_url",
  "display_name",
  // user.info.profile
  "bio_description",
  "profile_deep_link",
  "is_verified",
  "username",
  // user.info.stats
  "follower_count",
  "following_count",
  "likes_count",
  "video_count",
].join(",");

const VIDEO_FIELDS = [
  "id",
  "title",
  "video_description",
  "cover_image_url",
  "share_url",
  "embed_link",
  "duration",
  "create_time",
  "like_count",
  "comment_count",
  "share_count",
  "view_count",
].join(",");

// In-memory stores (MVP only — not persistent across deploys)
interface Account {
  user: TikTokUser;
  videos: TikTokVideo[];
  accessToken: string;
  videosError?: string;
}

interface Campaign {
  // Target number of videos to count the campaign as complete. 0 means unset.
  goal: number;
  // Video ids (TikTok ids are globally unique across accounts) that the user
  // has marked as meeting the campaign criteria.
  includedVideoIds: Set<string>;
}

interface Session {
  accounts: Account[];
  // open_id of selected account, or "combined"
  selected: string;
  campaign: Campaign;
}

const COMBINED = "combined";

function newCampaign(): Campaign {
  return { goal: 0, includedVideoIds: new Set<string>() };
}

const sessions = new Map<string, Session>();
const pkceStore = new Map<string, string>(); // state -> code_verifier

interface TikTokUser {
  // basic
  open_id: string;
  union_id?: string;
  avatar_url?: string;
  avatar_url_100?: string;
  avatar_large_url?: string;
  display_name?: string;
  // profile
  bio_description?: string;
  profile_deep_link?: string;
  is_verified?: boolean;
  username?: string;
  // stats
  follower_count?: number;
  following_count?: number;
  likes_count?: number;
  video_count?: number;
}

interface TikTokVideo {
  id: string;
  title?: string;
  video_description?: string;
  cover_image_url?: string;
  share_url?: string;
  embed_link?: string;
  duration?: number;
  create_time?: number;
  like_count?: number;
  comment_count?: number;
  share_count?: number;
  view_count?: number;
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

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatCount(n: number | undefined): string {
  if (n === undefined || n === null) return "—";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toString();
}

function formatDate(unix: number | undefined): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDuration(seconds: number | undefined): string {
  if (!seconds) return "0:00";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function renderPage(body: string, layout: "card" | "dashboard" = "card"): Response {
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
      background: #f5f5f5;
      color: #333;
    }
    body.layout-card {
      display: flex;
      align-items: center;
      justify-content: center;
    }
    body.layout-dashboard {
      padding: 2rem 1rem;
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
    .dashboard {
      max-width: 960px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }
    .panel {
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 2px 16px rgba(0,0,0,0.08);
      padding: 2rem;
    }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; }
    h2 { font-size: 1.15rem; margin-bottom: 1rem; color: #111; }
    .profile-header {
      display: flex;
      align-items: center;
      gap: 1.25rem;
      flex-wrap: wrap;
    }
    .avatar {
      width: 96px;
      height: 96px;
      border-radius: 50%;
      display: block;
      flex-shrink: 0;
      background: #eee;
    }
    .avatar-sm {
      width: 80px;
      height: 80px;
      margin: 0 auto 1rem;
    }
    .identity { flex: 1; min-width: 200px; }
    .display-name {
      font-size: 1.5rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    .verified {
      color: #fff;
      background: #20d5ec;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      font-size: 12px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
    }
    .username { color: #888; font-size: 0.95rem; margin-top: 0.1rem; }
    .bio { margin-top: 0.75rem; color: #444; line-height: 1.45; white-space: pre-wrap; }
    .profile-link {
      display: inline-block;
      margin-top: 0.75rem;
      color: #fe2c55;
      text-decoration: none;
      font-size: 0.9rem;
    }
    .profile-link:hover { text-decoration: underline; }
    .open-id { color: #aaa; font-size: 0.75rem; word-break: break-all; margin-top: 0.75rem; }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
    }
    .stat {
      background: #fafafa;
      border: 1px solid #eee;
      border-radius: 10px;
      padding: 1rem;
      text-align: center;
    }
    .stat-value { font-size: 1.5rem; font-weight: 700; color: #111; }
    .stat-label { font-size: 0.85rem; color: #888; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.03em; }

    .video-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 1.25rem;
    }
    .video {
      border: 1px solid #eee;
      border-radius: 10px;
      overflow: hidden;
      background: #fafafa;
      display: flex;
      flex-direction: column;
    }
    .video-cover {
      position: relative;
      aspect-ratio: 9 / 16;
      background: #000;
      overflow: hidden;
    }
    .video-cover img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      display: block;
    }
    .video-duration {
      position: absolute;
      bottom: 6px;
      right: 6px;
      background: rgba(0,0,0,0.7);
      color: #fff;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.75rem;
    }
    .video-body { padding: 0.75rem; display: flex; flex-direction: column; gap: 0.4rem; flex: 1; }
    .video-title {
      font-size: 0.9rem;
      font-weight: 600;
      color: #111;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }
    .video-date { font-size: 0.75rem; color: #999; }
    .video-stats {
      display: flex;
      gap: 0.75rem;
      font-size: 0.75rem;
      color: #666;
      margin-top: auto;
      flex-wrap: wrap;
    }
    .video-stat { display: inline-flex; gap: 0.2rem; align-items: center; }

    .empty { color: #888; text-align: center; padding: 2rem 0; }

    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .topbar h1 { margin: 0; }
    .topbar-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }

    .account-selector {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .account-option {
      position: relative;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 0.85rem;
      border: 2px solid #e5e5e5;
      border-radius: 999px;
      background: #fff;
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      color: #444;
      transition: border-color 0.15s, background 0.15s;
    }
    .account-option:hover { border-color: #ccc; }
    .account-option input { position: absolute; opacity: 0; pointer-events: none; }
    .account-option input:checked ~ .account-option-body {
      color: #000;
    }
    .account-option:has(input:checked) {
      border-color: #fe2c55;
      background: #fff0f3;
      color: #000;
    }
    .account-option .account-avatar {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background: #eee;
      object-fit: cover;
      display: block;
      flex-shrink: 0;
    }
    .account-option.combined {
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-size: 0.78rem;
      font-weight: 700;
    }
    .account-option.combined::before {
      content: "∑";
      font-size: 1rem;
      font-weight: 700;
    }

    .combined-profiles {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 0.75rem;
    }
    .combined-profile {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem;
      background: #fafafa;
      border: 1px solid #eee;
      border-radius: 10px;
    }
    .combined-profile .avatar-xs {
      width: 44px;
      height: 44px;
      border-radius: 50%;
      background: #eee;
      object-fit: cover;
      flex-shrink: 0;
    }
    .combined-profile-name { font-weight: 600; font-size: 0.95rem; color: #111; }
    .combined-profile-username { font-size: 0.8rem; color: #888; }

    .btn {
      display: inline-block;
      padding: 0.6rem 1.4rem;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.95rem;
      cursor: pointer;
      border: none;
      transition: opacity 0.15s;
    }
    .btn:hover { opacity: 0.85; }
    .btn-tiktok { background: #000; color: #fff; padding: 0.75rem 2rem; font-size: 1rem; }
    .btn-add { background: #fe2c55; color: #fff; padding: 0.55rem 1rem; font-size: 0.9rem; }
    .btn-logout { background: #e0e0e0; color: #333; padding: 0.55rem 1rem; font-size: 0.9rem; }
    .error { color: #c00; margin-bottom: 1rem; }
    .notice { background: #fff8e1; border: 1px solid #ffe082; color: #795500; padding: 0.75rem 1rem; border-radius: 8px; font-size: 0.9rem; }

    .campaign-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }
    .campaign-progress-text {
      font-size: 0.95rem;
      color: #444;
    }
    .campaign-progress-text strong { color: #111; font-size: 1.15rem; }
    .campaign-progress-text.complete strong { color: #0a8754; }
    .progress-bar {
      height: 10px;
      background: #eee;
      border-radius: 999px;
      overflow: hidden;
      margin-bottom: 1rem;
    }
    .progress-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #fe2c55, #ff6a00);
      transition: width 0.2s;
    }
    .progress-bar-fill.complete { background: #0a8754; }
    .campaign-controls {
      display: flex;
      gap: 0.5rem;
      align-items: center;
      flex-wrap: wrap;
    }
    .campaign-controls label {
      font-size: 0.9rem;
      color: #555;
    }
    .campaign-controls input[type="number"] {
      width: 90px;
      padding: 0.45rem 0.6rem;
      border: 1px solid #ccc;
      border-radius: 6px;
      font-size: 0.9rem;
    }
    .btn-goal { background: #111; color: #fff; padding: 0.5rem 1rem; font-size: 0.9rem; }
    .btn-clear { background: #eee; color: #444; padding: 0.5rem 1rem; font-size: 0.85rem; }
    .campaign-empty { color: #888; font-size: 0.9rem; }

    .video.included { border-color: #fe2c55; box-shadow: 0 0 0 2px #fff0f3 inset; }
    .video-include {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.45rem 0.6rem;
      border-top: 1px solid #eee;
      background: #fff;
      font-size: 0.8rem;
      color: #555;
      cursor: pointer;
      user-select: none;
    }
    .video-include input { margin: 0; cursor: pointer; }
    .video-include.checked { background: #fff0f3; color: #b3163b; font-weight: 600; }
    .video-include-form { margin: 0; }
  </style>
</head>
<body class="layout-${layout}">
  ${layout === "dashboard" ? `<div class="dashboard">${body}</div>` : `<div class="card">${body}</div>`}
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

function renderProfilePanel(user: TikTokUser): string {
  const avatarSrc = user.avatar_large_url ?? user.avatar_url ?? user.avatar_url_100;
  const avatar = avatarSrc
    ? `<img class="avatar" src="${escapeHtml(avatarSrc)}" alt="avatar" />`
    : `<div class="avatar"></div>`;
  const displayName = escapeHtml(user.display_name ?? "Unknown");
  const verified = user.is_verified ? `<span class="verified" title="Verified">✓</span>` : "";
  const username = user.username
    ? `<div class="username">@${escapeHtml(user.username)}</div>`
    : "";
  const bio = user.bio_description
    ? `<div class="bio">${escapeHtml(user.bio_description)}</div>`
    : "";
  const profileLink = user.profile_deep_link
    ? `<a class="profile-link" href="${escapeHtml(user.profile_deep_link)}" target="_blank" rel="noopener">View on TikTok →</a>`
    : "";

  return `
    <div class="panel">
      <div class="profile-header">
        ${avatar}
        <div class="identity">
          <div class="display-name">${displayName}${verified}</div>
          ${username}
          ${bio}
          ${profileLink}
          <div class="open-id">open_id: ${escapeHtml(user.open_id)}${user.union_id ? ` · union_id: ${escapeHtml(user.union_id)}` : ""}</div>
        </div>
      </div>
    </div>
  `;
}

function renderStatsPanel(user: TikTokUser): string {
  const stats: Array<[string, number | undefined]> = [
    ["Followers", user.follower_count],
    ["Following", user.following_count],
    ["Likes", user.likes_count],
    ["Videos", user.video_count],
  ];
  const cells = stats
    .map(
      ([label, value]) => `
        <div class="stat">
          <div class="stat-value">${formatCount(value)}</div>
          <div class="stat-label">${label}</div>
        </div>`,
    )
    .join("");
  return `
    <div class="panel">
      <h2>Stats</h2>
      <div class="stats-grid">${cells}</div>
    </div>
  `;
}

function renderCampaignPanel(session: Session, visibleVideos: TikTokVideo[]): string {
  const { goal, includedVideoIds } = session.campaign;
  const includedCount = includedVideoIds.size;

  // Count how many of the included videos are currently visible in this view —
  // e.g. in single-account view, included videos from other accounts still
  // count toward the overall campaign total, but this gives helpful context.
  const includedVisible = visibleVideos.filter((v) =>
    includedVideoIds.has(v.id)
  ).length;

  const pct =
    goal > 0 ? Math.min(100, Math.round((includedCount / goal) * 100)) : 0;
  const complete = goal > 0 && includedCount >= goal;

  const progress =
    goal > 0
      ? `
        <div class="campaign-progress-text ${complete ? "complete" : ""}">
          <strong>${includedCount} / ${goal}</strong> videos included${
            complete ? " · goal reached!" : ""
          }
          ${
            visibleVideos.length && includedVisible !== includedCount
              ? ` <span style="color:#888">(${includedVisible} in current view)</span>`
              : ""
          }
        </div>
        <div class="progress-bar">
          <div class="progress-bar-fill ${complete ? "complete" : ""}" style="width:${pct}%"></div>
        </div>`
      : `<div class="campaign-empty">No goal set yet. Enter a target number of videos below to start tracking.</div>`;

  const clearForm =
    goal > 0 || includedCount > 0
      ? `
        <form method="post" action="/campaign/clear" style="margin:0">
          <button type="submit" class="btn btn-clear">Reset campaign</button>
        </form>`
      : "";

  return `
    <div class="panel">
      <div class="campaign-header">
        <h2>Campaign goal</h2>
      </div>
      ${progress}
      <div class="campaign-controls">
        <form method="post" action="/campaign/goal" class="campaign-controls" style="margin:0">
          <label for="goal-input">Target videos:</label>
          <input id="goal-input" type="number" name="goal" min="0" step="1"
                 value="${goal || ""}" placeholder="e.g. 10" />
          <button type="submit" class="btn btn-goal">${goal > 0 ? "Update" : "Set goal"}</button>
        </form>
        ${clearForm}
      </div>
    </div>
  `;
}

function renderVideosPanel(
  videos: TikTokVideo[],
  includedVideoIds: Set<string>,
  error?: string,
): string {
  if (error) {
    return `
      <div class="panel">
        <h2>Videos</h2>
        <div class="notice">Could not load videos: ${escapeHtml(error)}</div>
      </div>
    `;
  }
  if (!videos.length) {
    return `
      <div class="panel">
        <h2>Videos</h2>
        <div class="empty">No videos yet.</div>
      </div>
    `;
  }

  const cards = videos
    .map((v) => {
      const cover = v.cover_image_url
        ? `<img src="${escapeHtml(v.cover_image_url)}" alt="cover" loading="lazy" />`
        : "";
      const title = escapeHtml(v.title || v.video_description || "Untitled");
      const href = v.share_url ?? v.embed_link;
      const titleEl = href
        ? `<a class="video-title" href="${escapeHtml(href)}" target="_blank" rel="noopener">${title}</a>`
        : `<div class="video-title">${title}</div>`;
      const included = includedVideoIds.has(v.id);
      const toggle = `
        <form method="post" action="/campaign/toggle" class="video-include-form">
          <input type="hidden" name="video_id" value="${escapeHtml(v.id)}" />
          <label class="video-include ${included ? "checked" : ""}">
            <input type="checkbox" ${included ? "checked" : ""}
                   onchange="this.form.submit()" />
            <span>${included ? "Included in campaign" : "Include in campaign"}</span>
          </label>
          <noscript><button type="submit" class="btn btn-clear" style="width:100%;border-radius:0">${included ? "Remove" : "Include"}</button></noscript>
        </form>`;
      return `
        <article class="video ${included ? "included" : ""}">
          <div class="video-cover">
            ${cover}
            <span class="video-duration">${formatDuration(v.duration)}</span>
          </div>
          <div class="video-body">
            ${titleEl}
            <div class="video-date">${formatDate(v.create_time)}</div>
            <div class="video-stats">
              <span class="video-stat">▶ ${formatCount(v.view_count)}</span>
              <span class="video-stat">♥ ${formatCount(v.like_count)}</span>
              <span class="video-stat">💬 ${formatCount(v.comment_count)}</span>
              <span class="video-stat">↗ ${formatCount(v.share_count)}</span>
            </div>
          </div>
          ${toggle}
        </article>`;
    })
    .join("");

  const includedCount = videos.filter((v) => includedVideoIds.has(v.id)).length;
  const heading = includedCount > 0
    ? `Videos (${videos.length}) · <span style="color:#fe2c55">${includedCount} included</span>`
    : `Videos (${videos.length})`;

  return `
    <div class="panel">
      <h2>${heading}</h2>
      <div class="video-grid">${cards}</div>
    </div>
  `;
}

function renderAccountSelector(session: Session): string {
  const showCombined = session.accounts.length >= 2;

  const accountOptions = session.accounts
    .map((acc) => {
      const { open_id, display_name, username, avatar_url_100, avatar_url } = acc.user;
      const avatarSrc = avatar_url_100 ?? avatar_url;
      const avatar = avatarSrc
        ? `<img class="account-avatar" src="${escapeHtml(avatarSrc)}" alt="" />`
        : `<span class="account-avatar"></span>`;
      const label = escapeHtml(display_name ?? username ?? open_id.slice(0, 8));
      const checked = session.selected === open_id ? "checked" : "";
      return `
        <label class="account-option">
          <input type="radio" name="account" value="${escapeHtml(open_id)}" ${checked}
                 onchange="this.form.submit()" />
          ${avatar}
          <span class="account-option-body">${label}</span>
        </label>`;
    })
    .join("");

  const combinedOption = showCombined
    ? `
      <label class="account-option combined">
        <input type="radio" name="account" value="${COMBINED}"
               ${session.selected === COMBINED ? "checked" : ""}
               onchange="this.form.submit()" />
        <span class="account-option-body">Combined</span>
      </label>`
    : "";

  return `
    <form method="get" action="/" class="account-selector">
      ${accountOptions}
      ${combinedOption}
      <noscript><button type="submit" class="btn btn-add">Switch</button></noscript>
    </form>
  `;
}

function renderCombinedProfilePanel(accounts: Account[]): string {
  const cards = accounts
    .map((acc) => {
      const { display_name, username, avatar_url_100, avatar_url } = acc.user;
      const avatarSrc = avatar_url_100 ?? avatar_url;
      const avatar = avatarSrc
        ? `<img class="avatar-xs" src="${escapeHtml(avatarSrc)}" alt="" />`
        : `<div class="avatar-xs"></div>`;
      const link = acc.user.profile_deep_link
        ? `<a class="profile-link" href="${escapeHtml(acc.user.profile_deep_link)}" target="_blank" rel="noopener">View →</a>`
        : "";
      return `
        <div class="combined-profile">
          ${avatar}
          <div>
            <div class="combined-profile-name">${escapeHtml(display_name ?? "Unknown")}</div>
            ${username ? `<div class="combined-profile-username">@${escapeHtml(username)}</div>` : ""}
            ${link}
          </div>
        </div>`;
    })
    .join("");

  return `
    <div class="panel">
      <h2>Combined view · ${accounts.length} accounts</h2>
      <div class="combined-profiles">${cards}</div>
    </div>
  `;
}

function sumField(
  accounts: Account[],
  field: keyof TikTokUser,
): number | undefined {
  let total = 0;
  let anyDefined = false;
  for (const acc of accounts) {
    const v = acc.user[field];
    if (typeof v === "number") {
      total += v;
      anyDefined = true;
    }
  }
  return anyDefined ? total : undefined;
}

function renderCombinedStatsPanel(accounts: Account[]): string {
  const stats: Array<[string, number | undefined]> = [
    ["Followers", sumField(accounts, "follower_count")],
    ["Following", sumField(accounts, "following_count")],
    ["Likes", sumField(accounts, "likes_count")],
    ["Videos", sumField(accounts, "video_count")],
  ];
  const cells = stats
    .map(
      ([label, value]) => `
        <div class="stat">
          <div class="stat-value">${formatCount(value)}</div>
          <div class="stat-label">${label}</div>
        </div>`,
    )
    .join("");
  return `
    <div class="panel">
      <h2>Combined stats</h2>
      <div class="stats-grid">${cells}</div>
    </div>
  `;
}

function userPage(session: Session): Response {
  const showCombined = session.selected === COMBINED && session.accounts.length >= 2;

  let heading: string;
  let profilePanel: string;
  let statsPanel: string;
  let videosPanel: string;
  let visibleVideos: TikTokVideo[];

  const included = session.campaign.includedVideoIds;

  if (showCombined) {
    heading = `Combined (${session.accounts.length} accounts)`;
    profilePanel = renderCombinedProfilePanel(session.accounts);
    statsPanel = renderCombinedStatsPanel(session.accounts);

    // Merge videos from all accounts; newest first.
    visibleVideos = session.accounts
      .flatMap((acc) => acc.videos)
      .sort((a, b) => (b.create_time ?? 0) - (a.create_time ?? 0));
    const mergedErrors = session.accounts
      .map((acc) => acc.videosError)
      .filter((e): e is string => !!e);
    const combinedError = mergedErrors.length ? mergedErrors.join("; ") : undefined;
    videosPanel = renderVideosPanel(visibleVideos, included, combinedError);
  } else {
    const active =
      session.accounts.find((a) => a.user.open_id === session.selected) ??
      session.accounts[0];
    heading = `Welcome, ${escapeHtml(active.user.display_name ?? "friend")}!`;
    profilePanel = renderProfilePanel(active.user);
    statsPanel = renderStatsPanel(active.user);
    visibleVideos = active.videos;
    videosPanel = renderVideosPanel(visibleVideos, included, active.videosError);
  }

  const campaignPanel = renderCampaignPanel(session, visibleVideos);

  const body = `
    <div class="topbar">
      <h1>${heading}</h1>
      <div class="topbar-actions">
        <a class="btn btn-add" href="/auth/tiktok">+ Add TikTok Account</a>
        <a class="btn btn-logout" href="/logout">Sign out</a>
      </div>
    </div>
    <div class="panel">
      ${renderAccountSelector(session)}
    </div>
    ${profilePanel}
    ${statsPanel}
    ${campaignPanel}
    ${videosPanel}
  `;
  return renderPage(body, "dashboard");
}

function errorPage(message: string): Response {
  return renderPage(`
    <h1>Something went wrong</h1>
    <p class="error">${escapeHtml(message)}</p>
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
  const url = `${TIKTOK_USER_URL}?fields=${USER_FIELDS}`;

  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const json = await res.json();
  console.dir({ userResponse: json }, { depth: null });

  if (json.error?.code && json.error.code !== "ok") {
    throw new Error(json.error?.message ?? "Failed to fetch user info");
  }

  return json.data.user as TikTokUser;
}

async function fetchVideos(accessToken: string): Promise<TikTokVideo[]> {
  const url = `${TIKTOK_VIDEO_LIST_URL}?fields=${VIDEO_FIELDS}`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ max_count: 20 }),
  });

  const json = await res.json();
  console.dir({ videoListResponse: json }, { depth: null });

  if (json.error?.code && json.error.code !== "ok") {
    throw new Error(json.error?.message ?? "Failed to fetch videos");
  }

  return (json.data?.videos ?? []) as TikTokVideo[];
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
    scope: "user.info.basic,user.info.profile,user.info.stats,video.list",
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

    // Video list is best-effort — failures shouldn't block sign-in.
    let videos: TikTokVideo[] = [];
    let videosError: string | undefined;
    try {
      videos = await fetchVideos(accessToken);
    } catch (err) {
      videosError = err instanceof Error ? err.message : String(err);
      console.error("Video list fetch error:", err);
    }

    console.dir({ authenticatedUser: user, videoCount: videos.length }, { depth: null });

    const newAccount: Account = { user, videos, accessToken, videosError };

    // If an existing session cookie points to a live session, append the
    // new account instead of starting a new session. Re-connecting the same
    // TikTok account (same open_id) replaces the prior entry so tokens refresh.
    const existingSessionId = getSessionId(req);
    const existingSession = existingSessionId
      ? sessions.get(existingSessionId)
      : null;

    let sessionId: string;
    if (existingSessionId && existingSession) {
      sessionId = existingSessionId;
      const dupIndex = existingSession.accounts.findIndex(
        (a) => a.user.open_id === user.open_id,
      );
      if (dupIndex >= 0) {
        existingSession.accounts[dupIndex] = newAccount;
      } else {
        existingSession.accounts.push(newAccount);
      }
      existingSession.selected = user.open_id;
    } else {
      sessionId = generateId();
      sessions.set(sessionId, {
        accounts: [newAccount],
        selected: user.open_id,
        campaign: newCampaign(),
      });
    }

    // PRG: redirect to "/" so refresh doesn't replay the callback.
    return new Response(null, {
      status: 302,
      headers: {
        location: "/",
        "set-cookie": setSessionCookie(sessionId),
      },
    });
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

// ── Campaign goal tracking ──────────────────────────────────────────────────
//
// Campaign state lives on the session and lets the signed-in user:
//   • Set a target number of videos for the campaign.
//   • Mark individual videos (across any of their connected accounts) as
//     meeting the campaign's inclusion criteria.
// Progress is then rendered as `<included> / <goal>` on the dashboard.

function requireSession(req: Request): Session | null {
  const sessionId = getSessionId(req);
  return sessionId ? sessions.get(sessionId) ?? null : null;
}

function ensureCampaign(session: Session): Campaign {
  // Defensive: older sessions (pre-feature) may lack a campaign field.
  if (!session.campaign) session.campaign = newCampaign();
  return session.campaign;
}

function redirectHome(): Response {
  return new Response(null, { status: 303, headers: { location: "/" } });
}

async function handleCampaignGoal(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { allow: "POST" },
    });
  }
  const session = requireSession(req);
  if (!session) return redirectHome();

  const form = await req.formData();
  const raw = form.get("goal");
  const parsed = Number(typeof raw === "string" ? raw : "");
  const goal = Number.isFinite(parsed) && parsed >= 0
    ? Math.floor(parsed)
    : 0;

  ensureCampaign(session).goal = goal;
  return redirectHome();
}

async function handleCampaignToggle(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { allow: "POST" },
    });
  }
  const session = requireSession(req);
  if (!session) return redirectHome();

  const form = await req.formData();
  const videoId = form.get("video_id");
  if (typeof videoId !== "string" || !videoId) return redirectHome();

  // Only allow toggling videos that actually belong to this session's accounts,
  // so a stray request can't inflate the progress counter.
  const known = session.accounts.some((acc) =>
    acc.videos.some((v) => v.id === videoId)
  );
  if (!known) return redirectHome();

  const campaign = ensureCampaign(session);
  if (campaign.includedVideoIds.has(videoId)) {
    campaign.includedVideoIds.delete(videoId);
  } else {
    campaign.includedVideoIds.add(videoId);
  }
  return redirectHome();
}

function handleCampaignClear(req: Request): Response {
  if (req.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { allow: "POST" },
    });
  }
  const session = requireSession(req);
  if (!session) return redirectHome();

  session.campaign = newCampaign();
  return redirectHome();
}

// ── Webhook handler ─────────────────────────────────────────────────────────
//
// TikTok delivers real-time event notifications to a registered callback URL
// via HTTPS POST. The request includes a `TikTok-Signature` header of the form
// `t=<unix_timestamp>,s=<hex_hmac_sha256>` where the signature is computed as
// HMAC-SHA256(client_secret, `<timestamp>.<raw_body>`).
//
// We must:
//   1. Respond 200 quickly (TikTok retries for 72h on non-2xx).
//   2. Verify the signature in constant time and reject stale timestamps.
//   3. Treat delivery as at-least-once and handle duplicates idempotently.
//
// See: https://developers.tiktok.com/doc/webhooks-overview

interface TikTokWebhookEvent {
  client_key: string;
  event: string;
  create_time: number;
  user_openid: string;
  // `content` is a JSON-serialized string per TikTok's spec.
  content: string;
}

// De-duplication ring buffer for at-least-once delivery. Keyed by a stable
// fingerprint of the event (client_key + event + user_openid + create_time).
const seenWebhookEvents = new Set<string>();
const SEEN_EVENTS_LIMIT = 1000;

function rememberWebhookEvent(key: string): boolean {
  if (seenWebhookEvents.has(key)) return false;
  if (seenWebhookEvents.size >= SEEN_EVENTS_LIMIT) {
    // Drop the oldest entry (Set preserves insertion order).
    const first = seenWebhookEvents.values().next().value;
    if (first !== undefined) seenWebhookEvents.delete(first);
  }
  seenWebhookEvents.add(key);
  return true;
}

function parseSignatureHeader(
  header: string | null,
): { timestamp: number; signature: string } | null {
  if (!header) return null;
  let timestamp: number | undefined;
  let signature: string | undefined;
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === "t") timestamp = Number(v);
    else if (k === "s") signature = v;
  }
  if (!signature || !Number.isFinite(timestamp)) return null;
  return { timestamp: timestamp as number, signature };
}

async function computeWebhookSignature(
  secret: string,
  timestamp: number,
  rawBody: string,
): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(`${timestamp}.${rawBody}`),
  );
  return [...new Uint8Array(sigBuf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Constant-time comparison to avoid leaking signature bytes via timing.
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function removeAccountByOpenId(openId: string): number {
  let removed = 0;
  for (const [sessionId, session] of sessions) {
    const before = session.accounts.length;
    session.accounts = session.accounts.filter(
      (a) => a.user.open_id !== openId,
    );
    removed += before - session.accounts.length;
    if (!session.accounts.length) {
      sessions.delete(sessionId);
    } else if (session.selected === openId) {
      session.selected = session.accounts[0].user.open_id;
    }
  }
  return removed;
}

function handleWebhookEvent(event: TikTokWebhookEvent): void {
  let parsedContent: unknown = event.content;
  try {
    parsedContent = JSON.parse(event.content);
  } catch {
    // `content` is documented as a JSON string but tolerate malformed values.
  }

  console.dir(
    {
      tiktokWebhook: {
        event: event.event,
        user_openid: event.user_openid,
        create_time: event.create_time,
        content: parsedContent,
      },
    },
    { depth: null },
  );

  switch (event.event) {
    case "authorization.removed": {
      // The user's access_token has already been revoked by TikTok. Drop any
      // in-memory account state so we don't keep trying to use a dead token.
      const removed = removeAccountByOpenId(event.user_openid);
      console.log(
        `[webhook] authorization.removed for ${event.user_openid} — purged ${removed} account(s)`,
      );
      break;
    }
    default:
      // Unknown / unsubscribed-by-default event types are still acknowledged
      // with 200 so TikTok stops retrying. Add explicit handlers as needed.
      break;
  }
}

async function handleWebhook(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { allow: "POST" },
    });
  }

  if (!TIKTOK_CLIENT_SECRET) {
    console.error("[webhook] TIKTOK_CLIENT_SECRET is not configured");
    return new Response("Server misconfigured", { status: 500 });
  }

  const rawBody = await req.text();
  const sig = parseSignatureHeader(req.headers.get("tiktok-signature"));
  if (!sig) {
    console.warn("[webhook] missing or malformed TikTok-Signature header");
    return new Response("Invalid signature", { status: 401 });
  }

  const expected = await computeWebhookSignature(
    TIKTOK_CLIENT_SECRET,
    sig.timestamp,
    rawBody,
  );
  if (!timingSafeEqual(expected, sig.signature)) {
    console.warn("[webhook] signature mismatch");
    return new Response("Invalid signature", { status: 401 });
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - sig.timestamp) > WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS) {
    console.warn(
      `[webhook] stale timestamp: header=${sig.timestamp} now=${nowSec}`,
    );
    return new Response("Stale timestamp", { status: 401 });
  }

  let payload: TikTokWebhookEvent;
  try {
    payload = JSON.parse(rawBody) as TikTokWebhookEvent;
  } catch (err) {
    console.error("[webhook] invalid JSON body:", err);
    return new Response("Invalid payload", { status: 400 });
  }

  if (!payload.event || !payload.client_key) {
    return new Response("Invalid payload", { status: 400 });
  }

  // Best-effort defense against the same event being processed twice.
  const dedupeKey = `${payload.client_key}:${payload.event}:${payload.user_openid}:${payload.create_time}`;
  if (!rememberWebhookEvent(dedupeKey)) {
    console.log(`[webhook] duplicate event ignored: ${dedupeKey}`);
    return new Response("OK", { status: 200 });
  }

  try {
    handleWebhookEvent(payload);
  } catch (err) {
    // Always 200 once the signature checks out — failures here would just cause
    // TikTok to redeliver, which won't help an internal logic bug. Log and move on.
    console.error("[webhook] handler error:", err);
  }

  return new Response("OK", { status: 200 });
}

// ── Server ──────────────────────────────────────────────────────────────────

Deno.serve({ port: 8000 }, async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  const path = url.pathname;

  if (path === "/auth/tiktok") return await handleAuthStart();
  if (path === REDIRECT_PATH) return await handleCallback(req);
  if (path === WEBHOOK_PATH) return await handleWebhook(req);
  if (path === "/logout") return handleLogout(req);
  if (path === "/campaign/goal") return await handleCampaignGoal(req);
  if (path === "/campaign/toggle") return await handleCampaignToggle(req);
  if (path === "/campaign/clear") return handleCampaignClear(req);

  // Home — show user page if session exists, otherwise sign-in.
  // Supports ?account=<open_id|combined> to toggle the active view.
  if (path === "/") {
    const sessionId = getSessionId(req);
    const session = sessionId ? sessions.get(sessionId) : null;
    if (!session) return homePage();
    ensureCampaign(session);

    const requested = url.searchParams.get("account");
    if (requested) {
      const isCombined =
        requested === COMBINED && session.accounts.length >= 2;
      const matchesAccount = session.accounts.some(
        (a) => a.user.open_id === requested,
      );
      if (isCombined || matchesAccount) {
        session.selected = requested;
        // Redirect to clean URL so the selection is reflected without the
        // query param lingering on refresh.
        return new Response(null, {
          status: 302,
          headers: { location: "/" },
        });
      }
    }

    return userPage(session);
  }

  return new Response("Not found", { status: 404 });
});
