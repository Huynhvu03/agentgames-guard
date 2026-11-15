# LogiGuard — Windows Run Guide

Guard server for zkVerify **Agent Games Season 01, Wildcard track**.
Agent name: **LogiGuard** · Repo (to be created on upload):
https://github.com/Huynhvu03/agentgames-guard

> The Gatekeeper server already runs on this PC on **port 3000** with its
> own cloudflared tunnel. **Do not stop it, do not change it.**
> LogiGuard runs beside it on **port 3001** with a **second** tunnel.

## 1. Prerequisites (already installed for Gatekeeper)

- Node.js LTS v20+ (this PC: v24.15.0) — `node --version`
- Git — `git --version`
- cloudflared — `C:\tools\cloudflared.exe`

## 2. Get the code (new folder — do NOT reuse the Gatekeeper folder)

```powershell
git clone https://github.com/Huynhvu03/agentgames-guard.git
cd agentgames-guard
npm install
```

Files in the repo: `server.js`, `package.json`, `test-guard.js`,
`.env.example`, `.gitignore`, `README.md`, `SUBMISSION.md`,
`README-WINDOWS-GUARD.md` (this file).

## 3. Create `.env` (optional — defaults already work)

```powershell
copy .env.example .env
notepad .env
```

```ini
RPC_URL=https://ethereum.publicnode.com
PORT=3001
```

No secret, no API key, no wallet — nothing sensitive goes in `.env`.

## 4. Start the server (port 3001)

```powershell
npm start
```

You should see:

```text
LogiGuard listening on http://localhost:3001 (POST /guard, GET /health)
```

Check it in a second PowerShell window:

```powershell
curl.exe http://localhost:3001/health
```

→ `{"ok":true,"agent":"LogiGuard",...}` (plus the live chain id).

Try the demo page in a browser: `http://localhost:3001/` — it has two
forms and worked examples (DAI allowance of vitalik.eth to Uniswap
Permit2, and an unlimited USDC approve).

## 5. Expose it with a SECOND cloudflared tunnel

In another PowerShell window:

```powershell
cloudflared tunnel --url http://localhost:3001
```

cloudflared prints a public URL like:

```text
https://<name>.trycloudflare.com
```

This is a **quick tunnel — no account needed**. It is a DIFFERENT URL
from the Gatekeeper tunnel (port 3000) — keep both tunnels running.

Test the public URL:

```powershell
curl.exe https://<name>.trycloudflare.com/health
```

→ must return the same `{"ok":true,...}` JSON. The guard endpoint is
`https://<name>.trycloudflare.com/guard`.

## 6. Submit to the Wildcard track

1. Open the Agent Games dashboard → Wildcard submission form.
2. Fill it in from `SUBMISSION.md` in the repo (fields in form order).
   Replace every `<tunnel>` placeholder with the public URL from step 5
   (e.g. `https://<name>.trycloudflare.com/guard`).
3. PROOF REFERENCE stays blank (no proof in v1 — stated honestly in the
   submission).
4. Submit. Judging is manual, 22–30/11/2026.

## 7. Optional bonus: public share

The track gives a bonus for sharing the build publicly — what the agent
is and a public demo. Post a short thread on X (@0xlogi_) with the repo
link and the demo URL, then add that post link to ADDITIONAL LINKS in
the submission if the form still allows edits.

## During the event (until 21/11, judging until 30/11)

- Keep the PC on and both servers + both tunnels running while the
  Wildcard entry is live, so reviewers can reach the endpoint.
- If a tunnel drops or the PC restarts: start the server, start the
  tunnel again, copy the **new** URL, and update the submission form /
  demo links if they can still be edited (quick-tunnel URLs change on
  every restart).
- Never sign anything with this agent and never paste a private key or
  seed phrase anywhere — LogiGuard does not need them and must never see
  them.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `EADDRINUSE` on port 3001 | Another LogiGuard is already running — check the other PowerShell window instead of starting a second one. |
| `EADDRINUSE` on port 3000 | That is the Gatekeeper server — do not touch it; LogiGuard uses 3001. |
| `/guard` returns 502 "Could not read on-chain data" | The public RPC is unreachable from this network. Retry in a minute; check `RPC_URL` in `.env` (default publicnode, fallback llamarpcc). The agent never fabricates verdicts. |
| `/health` shows chain_id null | RPC unreachable — same as above; the server still runs, guard calls will 502 honestly. |
| Tunnel URL changed | Expected for quick tunnels — copy the new URL and update the submission/demo links. |
