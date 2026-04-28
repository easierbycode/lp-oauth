# lp-oauth

## Setup

1. Copy `.env.example` to `.env` and fill in `TIKTOK_CLIENT_KEY` / `TIKTOK_CLIENT_SECRET` from your TikTok app at https://developers.tiktok.com/apps.
2. In the TikTok app settings, add `http://localhost:8000/auth/tiktok/callback` as an allowed Redirect URI.
3. Run:
   ```
   deno task dev
   ```
4. Open http://localhost:8000 and click "Sign in with TikTok".
