# KMS for MSA

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
- Key exchange hardening: RSA-OAEP unwrap binds to `{sessionId}:{token}` as OAEP label when possible. Legacy clients without a label remain supported.
 - Header validation: `X-Client-Token` is validated consistently across routes (base64url body with optional server prefix); `X-Request-Id` is validated and echoed.

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

### Docker E2E

Docker Compose runs the KMS and the E2E client (with both positive and negative tests):

```bash
docker compose up --build --abort-on-container-exit
```

Compose config sets low rate limits for predictable 429s and uses a valid demo token.

## Configuration

- `KMS_PORT` (default `3000`)
- `KMS_WHITELIST` (CSV; default `100.64.0.9`)
- `KEY_STORE_PATH` (default `./data/keys`)
- `KMS_SESSION_TTL_MS` (default `900000`)
- `KMS_SESSION_SLIDING` (`true|false`, default `true`)
- `KMS_ROTATE_WINDOW_MS` (default `10000`)
- `KMS_ROTATE_MAX` (default `5`)
- `KMS_TOKEN_PREFIX` (optional, prepended to issued tokens)
- `KMS_CRYPTO_WINDOW_MS` (default `10000`) and `KMS_CRYPTO_MAX` (default `50`) for `/crypto/*` rate limiting
- `KMS_KEYS_WINDOW_MS` (default `10000`) and `KMS_KEYS_MAX` (default `20`) for `/keys/*` rate limiting
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
- Request rate limiting for `/crypto/*` and `/keys/*` endpoints (429 with `Retry-After`)
- Sliding expiration configurable for sessions
- Request/response structured logging and audit events (key-exchange, rotate)
- Local filesystem keystore uses atomic writes
- Trust proxy restricted to local networks
- Request IDs: every response includes `X-Request-Id` and logs include `requestId` for traceability
- Header validation: `X-Client-Token` format and `X-Request-Id` shape validated
