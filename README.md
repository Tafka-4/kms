# Personal KMS Scaffold

A secure-by-default KMS scaffold for a personal cloud storage system. It enforces IP whitelisting, negotiates a pre-REST AES session key via RSA-OAEP, supports token-based client identity, provides AES-256-GCM crypto endpoints, versioned data key generation/rotation, and serves OpenAPI docs.

## Quick Start

- Requirements: Node.js 18+
- Install deps:

```bash
npm install
```

- Configure (optional): copy `.env.example` to `.env` and set values:
  - `KMS_PORT` (default `3000`)
  - `KMS_WHITELIST` (CSV; default `100.64.0.9`)
  - `KEY_STORE_PATH` (default `./data/keys`)
  - `NODE_ENV`

- Dev (auto-reload):

```bash
npm run dev
```

- Build + run:

```bash
npm run build
npm start
```

- Docs: visit `http://localhost:3000/docs`

## Security Model

- Pre-REST session: client GETs `/session/init` to fetch the RSA-4096 public key and a `sessionId`. Client generates a random 32-byte AES key and POSTs it wrapped with RSA-OAEP(SHA-256) to `/session/key-exchange` with header `X-Client-Token`.
- Server unwraps and binds the session key to the token and `sessionId` in a TTL store (default configurable). All crypto/key endpoints require the token and use the bound session key.
- Token rotation: After key-exchange, client rotates its token via `POST /session/rotate-token` (server-generated or client-supplied). Rotation optionally refreshes TTL (sliding expiration).
- Data encryption: AES-256-GCM (12-byte IV, 16-byte tag, optional AAD). IVs are random per operation.
- Ed25519 helpers are provided for optional audit signing.
- IP whitelist: enforced globally; app is proxy-aware with restricted trust proxy. Set `KMS_WHITELIST` appropriately for your network.
- Production: Always run behind TLS (HTTPS). This demo crypto layer complements but does not replace TLS.

## Key Management

- Versioned data keys are stored in a local JSON file at `KEY_STORE_PATH` with metadata `{ keyId, version, createdAt, status }` and rotation support. Old versions remain readable during a 7-day grace period.
- Endpoints:
  - `POST /keys/generate` → new keyId/version
  - `POST /keys/rotate` with `{ keyId }` → new active version
  - `GET /keys/:keyId` → metadata

## API Docs

- OpenAPI at `/docs`.
- See `docs/api.md` for concise examples.

## Client Test

- A simple test client is provided at `client/testE2E.mjs`.

```bash
npm run test:client
```

Notes:
- Ensure `KMS_WHITELIST` includes your client IP (or permissive for local).
- The keystore path is created if missing; the process exits non-zero if not writable.

## Configuration

- `KMS_PORT` (default `3000`)
- `KMS_WHITELIST` (CSV; default `100.64.0.9`)
- `KEY_STORE_PATH` (default `./data/keys`)
- `KMS_SESSION_TTL_MS` (default `900000`)
- `KMS_SESSION_SLIDING` (`true|false`, default `true`)
- `KMS_ROTATE_WINDOW_MS` (default `10000`)
- `KMS_ROTATE_MAX` (default `5`)
- `KMS_TOKEN_PREFIX` (optional, prepended to issued tokens)
- Security headers are enabled by default (HSTS in production behind HTTPS).
- Background GC removes expired sessions periodically.

Client:
- `BASE_URL` (e.g., `http://localhost:3000`)
- `TOKEN` (optional; random if unset)
- `ROTATE_INTERVAL_MS` (optional; periodic token rotation demo)

## Security Checklist

- Input validation via Zod on all JSON bodies
- IP whitelisting on every request
- AES-256-GCM with random IV, auth tag, optional AAD
- RSA-OAEP(SHA-256) for wrapping session key
- Session token format validation, rotation endpoint with rate limiting
- Sliding expiration configurable for sessions
- Request/response structured logging and audit events (key-exchange, rotate)
- Local filesystem keystore uses atomic writes
- Trust proxy restricted to local networks

## Development

- Type-check:

```bash
npx tsc --noEmit
```

- Build output is emitted to `build/`. Do not commit `build/`.

## Limitations

- In-memory sessions (single-process). Use a shared store for horizontal scaling.
- Local filesystem key storage for demo only; integrate an HSM/secret manager for production.

