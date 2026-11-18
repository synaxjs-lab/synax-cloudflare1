# SYNAX — Fresh Cloudflare rebuild

This version keeps the existing SYNAX React interface and rebuilds the active backend around Cloudflare services only:

- **Workers**: HTTP API and authentication.
- **D1**: chat messages, app state, sessions, usage, call signaling, and upload bookkeeping.
- **R2**: private images, videos, voice notes, documents, and chat-background files.
- **Durable Objects**: WebSocket realtime delivery, presence, and the retryable pending-message queue.

The active Cloudflare deployment does not call Supabase. `legacy/railway/server.ts` is the original Railway backend, preserved byte-for-byte for reference and not imported by `worker/index.ts`.

## Free-tier design targets

The application is designed to start within the Cloudflare Free plan, not to provide unlimited storage or unlimited usage. Current plan limits can change. On Free, D1 is limited to 500 MB per database (5 GB total per account), 5 million row reads/day and 100,000 row writes/day; R2 includes 10 GB-month Standard storage, 1 million Class A and 10 million Class B operations/month; Workers allow 100,000 requests/day and 10 ms CPU per invocation; SQLite-backed Durable Objects allow 100,000 requests/day and share a 5 GB storage allowance per account. Exceeding a Free limit causes operations of that type to fail until the relevant quota resets; stored data is not deleted by a D1 daily row quota. This app is designed for low-volume two-person use, not unlimited or guaranteed-free hosting. Monitor usage before relying on the free tier for important communication.

## 1. Install dependencies and authenticate with Cloudflare

Use Node.js 22 or newer, then run:

```bash
npm install
npx wrangler login
```

## 2. Create a new D1 database

```bash
npx wrangler d1 create synax-db
```

Copy the returned `database_id` into the `d1_databases[0].database_id` field in `wrangler.jsonc`, replacing `REPLACE_WITH_D1_DATABASE_ID`.

## 3. Create the private R2 bucket

```bash
npx wrangler r2 bucket create synax-private-media
```

Do not enable public `r2.dev` access. SYNAX serves media through its signed `/api/media` route.

## 4. Set Worker secrets

Set three different passwords, each at least 12 characters long:

```bash
npx wrangler secret put SYNAX_PERSON_1_PASSWORD
npx wrangler secret put SYNAX_PERSON_2_PASSWORD
npx wrangler secret put SYNAX_ADMIN_PASSWORD
npx wrangler secret put SYNAX_MEDIA_SIGNING_SECRET
```

Generate the media-signing secret locally. For example, on macOS/Linux:

```bash
openssl rand -hex 32
```

Do not commit secrets, paste them into chat, or expose them in frontend environment variables. For local development, copy `.dev.vars.example` to `.dev.vars` and replace the placeholders. `.dev.vars` is ignored by Git.

## 5. Apply the new D1 schema

```bash
npm run d1:migrate:remote
```

For local development, use:

```bash
npm run d1:migrate:local
```

This creates the fresh SYNAX tables. The first successful API startup creates the initial application state row and hashes the three configured passwords using Web Crypto PBKDF2. Later Worker cold starts load the existing state and do not repeat the initial password hashing.

## 6. Verify and run

Run the isolated D1 adapter test first:

```bash
npm run test:d1
```

Then run the full project checks after dependencies have installed:

```bash
npm run typecheck
npm run build
npm run dev
```

The local Worker uses local D1 and R2 resources. Keep `.dev.vars` private. Before production deployment, verify authentication from two separate browser profiles, send messages both ways, refresh both clients, disconnect/reconnect the network, and test private media uploads/downloads including video byte-range playback.

### Current verification status

The included D1 adapter test passes against a local SQLite database, and the TypeScript/TSX files passed a syntax-transpilation check in the preparation environment. A full dependency-based TypeScript typecheck, Vite production build, Wrangler local Worker runtime test, and live two-device test have **not** been completed. Do not treat this package as production-verified until those checks pass after `npm install` and Cloudflare resources are configured.

## 7. Deploy

```bash
npm run deploy
```

This deploys as `synax-cloudflare-rebuild`, a separate Worker name so the existing deployment is not overwritten during initial testing. After testing the new Worker on its `workers.dev` address, attach your custom domain or update routing deliberately.

## Two-person account model

There is no public sign-up endpoint. The only chat identities are `person_1` and `person_2`; the admin portal is a separate privileged control account. The initial passwords come from Worker secrets and are not hard-coded in source.

## Upload behavior

- Direct R2 uploads are used for small files and voice notes (up to 25 MB).
- Images/videos larger than 5 MiB use R2 multipart upload in sequential 5 MiB parts.
- The enforced maximum for resumable media is 50 MB.
- R2 bucket remains private. Message rows store a signed same-origin media URL; possession of that URL grants access to that object, so don't share it publicly.
- Incomplete multipart uploads older than 48 hours are cleaned up by the daily scheduled Worker.

## Reliability notes and limits

The Durable Object persists a new message in its storage queue before acknowledging the realtime enqueue; it retries persistence to D1 when needed. Its daily request budget includes HTTP requests, WebSocket messages and alarm invocations, so frequent heartbeats and reconnect loops must be avoided. The client also reconciles canonical history from D1 after reconnect or refresh. D1 remains the long-term message history. This improves resilience to transient D1/network delays, but a prolonged Cloudflare quota outage can still prevent delivery or persistence. Keep monitoring D1, Workers, Durable Objects, and R2 usage.

Voice/video calls still depend on browser WebRTC and ICE connectivity. Optional Cloudflare Calls TURN credentials can improve connectivity in restrictive networks and may have separate pricing; they are not guaranteed to be free. Verify calls independently before treating them as production-ready.

## Original Railway server

`legacy/railway/server.ts` is preserved unchanged and is not the active entry point. The default `dev`, `build`, and `deploy` scripts target Wrangler/Cloudflare only. The original Supabase/Railway notes are archived under `legacy/` and are not used by the active runtime.
