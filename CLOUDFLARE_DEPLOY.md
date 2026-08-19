# Cloudflare Worker deployment

This project uses a Vite frontend, a Worker for `/api/*`, Workers Static Assets for the SPA, and a D1 database. The database stores WebAuthn credential public keys and counters; the laptop or phone authenticator keeps the private key and biometric template.

## Git-connected Worker settings

- Repository: `ttejas12web/fingerprint`
- Production branch: `main`
- Build command: `pnpm run build` (or `npm run build`)
- Deploy command: `pnpm exec wrangler deploy`
- Root directory: `/`
- D1 binding: `DB` -> `fingerprint-db`

`wrangler.jsonc` is the deployment source of truth. It routes `/api/*` through `worker/index.ts` and serves the Vite build from `dist` for every other route. After creating `fingerprint-db`, add its UUID as `database_id` in that file.

## Database setup

```sh
pnpm install
pnpm exec wrangler d1 create fingerprint-db --location apac
pnpm run types
pnpm run db:migrate:remote
```

For local development, run `pnpm run db:migrate:local`, then `pnpm run dev`.

## WebAuthn requirements

- Use HTTPS in production; `*.pages.dev` is suitable.
- Enroll credentials again after changing to a different hostname. WebAuthn credentials are scoped to the relying-party domain.
- Test in a top-level Safari, Chrome, or Edge window. Embedded previews can block WebAuthn.
- The browser and operating system verify Touch ID, Windows Hello, a PIN, or another authenticator locally. The website cannot read raw fingerprint images or identify which physical finger was used.
