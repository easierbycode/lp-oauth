// Starts ngrok, writes the public URL into .env as BASE_URL, then runs the
// dev server. Both children are killed on exit so Ctrl+C cleans up cleanly.
//
// Set NGROK_DOMAIN in .env (paid ngrok feature) to get a stable URL — otherwise
// you'll need to re-register the redirect URI in the TikTok portal after every
// restart.

const ENV_PATH = ".env";
const PORT = 8000;
// ngrok's default agent API port (4040) collides with Docker Desktop on macOS.
// Pick something less popular and tell ngrok to bind there.
const NGROK_WEB_ADDR = "127.0.0.1:4141";
const NGROK_API = `http://${NGROK_WEB_ADDR}/api/tunnels`;

// ngrok wants a bare hostname; tolerate users pasting a full URL.
const domain = Deno.env.get("NGROK_DOMAIN")
  ?.trim()
  .replace(/^https?:\/\//, "")
  .replace(/\/+$/, "");

// If another ngrok is already running on our chosen web addr, our spawn will
// fail to bind it and our poll could return the stale tunnel's URL. Bail
// early — but only if the responder actually looks like ngrok (has a
// `tunnels` array), since unrelated services may bind the same port.
async function ngrokAlreadyRunning(): Promise<boolean> {
  try {
    const res = await fetch(NGROK_API);
    if (!res.ok) return false;
    const json = await res.json();
    return Array.isArray(json?.tunnels);
  } catch {
    return false;
  }
}
if (await ngrokAlreadyRunning()) {
  console.error(
    `Another ngrok agent is already running (API live at ${NGROK_API}).\n` +
      `Stop it before running dev:tunnel — e.g. \`pkill ngrok\`.`,
  );
  Deno.exit(1);
}

// ngrok 3 only exposes web_addr via config file, not CLI. Build a temp config
// that copies the user's existing config (so authtoken etc. carry over) and
// overrides web_addr to our chosen port.
async function buildNgrokConfig(webAddr: string): Promise<string> {
  const home = Deno.env.get("HOME") ?? "";
  const candidates = [
    `${home}/Library/Application Support/ngrok/ngrok.yml`,
    `${home}/.config/ngrok/ngrok.yml`,
  ];
  let base = "";
  for (const p of candidates) {
    try {
      base = await Deno.readTextFile(p);
      break;
    } catch { /* try next */ }
  }
  if (!base) {
    base = `version: "3"\n`;
  } else if (!base.endsWith("\n")) {
    base += "\n";
  }
  // Drop any existing top-level web_addr line, then append our override.
  base = base.replace(/^web_addr:.*\n?/m, "");
  base += `web_addr: ${webAddr}\n`;

  const tmp = await Deno.makeTempFile({ prefix: "ngrok-", suffix: ".yml" });
  await Deno.writeTextFile(tmp, base);
  return tmp;
}

const configPath = await buildNgrokConfig(NGROK_WEB_ADDR);

const ngrokArgs = [
  "http",
  String(PORT),
  "--log=stdout",
  "--config",
  configPath,
];
if (domain) ngrokArgs.push(`--domain=${domain}`);

const ngrok = new Deno.Command("ngrok", {
  args: ngrokArgs,
  stdout: "null",
  stderr: "inherit",
}).spawn();

async function waitForTunnel(timeoutMs = 15_000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(NGROK_API);
      if (res.ok) {
        const json = await res.json();
        const https = json.tunnels?.find(
          (t: { public_url?: string }) => t.public_url?.startsWith("https://"),
        );
        if (https?.public_url) return https.public_url;
      }
    } catch {
      // ngrok API not up yet — retry.
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("ngrok did not produce a public URL within 15s");
}

let publicUrl: string;
try {
  publicUrl = await waitForTunnel();
} catch (err) {
  console.error(err);
  ngrok.kill("SIGTERM");
  Deno.exit(1);
}

if (domain && !publicUrl.includes(domain)) {
  console.error(
    `Tunnel URL ${publicUrl} doesn't match requested NGROK_DOMAIN=${domain}.\n` +
      `Likely a stale ngrok agent — try \`pkill ngrok\` and re-run.`,
  );
  ngrok.kill("SIGTERM");
  Deno.exit(1);
}

console.log(`\nngrok tunnel: ${publicUrl}`);
console.log(
  `Register ${publicUrl}/auth/tiktok/callback as a Redirect URI in the TikTok app.\n`,
);

let env = "";
try {
  env = await Deno.readTextFile(ENV_PATH);
} catch {
  // No .env yet — we'll create it.
}
const baseLine = `BASE_URL=${publicUrl}`;
if (/^BASE_URL=.*/m.test(env)) {
  env = env.replace(/^BASE_URL=.*/m, baseLine);
} else {
  if (env.length && !env.endsWith("\n")) env += "\n";
  env += baseLine + "\n";
}
await Deno.writeTextFile(ENV_PATH, env);

const dev = new Deno.Command("deno", {
  args: [
    "run",
    "--allow-net",
    "--allow-env",
    "--env-file=.env",
    "--watch",
    "main.ts",
  ],
  stdout: "inherit",
  stderr: "inherit",
  stdin: "inherit",
}).spawn();

const shutdown = () => {
  try { ngrok.kill("SIGTERM"); } catch { /* already dead */ }
  try { dev.kill("SIGTERM"); } catch { /* already dead */ }
};
Deno.addSignalListener("SIGINT", shutdown);
Deno.addSignalListener("SIGTERM", shutdown);

const status = await dev.status;
try { ngrok.kill("SIGTERM"); } catch { /* already dead */ }
Deno.exit(status.code);
