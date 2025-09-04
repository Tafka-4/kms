# Personal KMS API

- Base URL: `http://<host>:<port>` (default `3000`)
- Auth: Send `X-Client-Token: <your-token>` for protected routes.
- IP whitelist: Only requests from `KMS_WHITELIST` are allowed.
- Transport security: Use TLS in production; this demo layer does not replace TLS.

## Flow

1) GET `/session/init`
- Response:
```
{ "data": { "sessionId": "...", "rsaPublicKeyPem": "-----BEGIN PUBLIC KEY-----..." } }
```

2) POST `/session/key-exchange`
- Headers: `X-Client-Token: <token>`
- Body:
```
{ "sessionId": "...", "wrappedKey": "<base64>" }
```
- `wrappedKey` is RSA-OAEP(SHA-256) of a 32-byte random AES key.

3) POST `/crypto/encrypt`
- Headers: `X-Client-Token`
- Body:
```
{ "algorithm": "AES-256-GCM", "plaintext": "<base64>", "aad": "<base64-optional>" }
```
- Response:
```
{ "data": { "ciphertext": "<base64>", "iv": "<base64>", "tag": "<base64>" } }
```

4) POST `/crypto/decrypt`
- Headers: `X-Client-Token`
- Body:
```
{ "algorithm": "AES-256-GCM", "ciphertext": "<base64>", "iv": "<base64>", "tag": "<base64>", "aad": "<base64-optional>" }
```
- Response:
```
{ "data": { "plaintext": "<base64>" } }
```

5) POST `/session/rotate-token`
- Headers: `X-Client-Token: <current-token>`
- Body (optional):
```
{ "token": "<desired-new-token>" }
```
- Response:
```
{ "data": { "newToken": "...", "expiresAt": 173... } }
```

## Key Management

- POST `/keys/generate` → `{ data: { keyId, version } }`
- POST `/keys/rotate` body `{ keyId }` → `{ data: { keyId, version } }`
- GET `/keys/:keyId` → `{ data: { keyId, createdAt, versions:[{ version, createdAt, status, expiresAt? }] } }`

## Errors

Uniform shape:
```
{ "error": { "code": "STRING", "message": "Human readable", "details": {} }}
```

## Notes
- AES-256-GCM uses 12-byte IV and 16-byte auth tag.
- Sessions expire after a configurable TTL (`KMS_SESSION_TTL_MS`) with optional sliding refresh on rotation.
- Token rotation is rate-limited (window and max are configurable).
- Security headers are applied; HSTS is enabled in production behind HTTPS.
- Expired sessions are periodically garbage-collected.
- Do not expose stored key material in responses.
- Use TLS (HTTPS) in production; terminate TLS before this service.

