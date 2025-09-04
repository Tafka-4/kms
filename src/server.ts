import express from 'express';
import { loadConfig } from './config.js';
import { ipWhitelist } from './security/ipWhitelist.js';
import { sessionRouter } from './routes/session.js';
import { cryptoRouter } from './routes/crypto.js';
import { keysRouter } from './routes/keys.js';
import swaggerUi from 'swagger-ui-express';
import { openapiSpec } from './docs/openapi.js';
import { requestLogger } from './middleware/logger.js';
import { secureHeaders } from './middleware/secureHeaders.js';
import { sessions } from './security/session.js';

const cfg = loadConfig();

const app = express();
app.set('trust proxy', 'loopback, linklocal, uniquelocal');
app.use(express.json({ limit: '1mb' }));
app.use(requestLogger);
app.use(secureHeaders());

// IP whitelist
app.use(ipWhitelist(cfg.whitelist));

// Health
app.get('/health', (_req, res) => res.json({ data: { ok: true } }));

// Docs
app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapiSpec as any));

// Routes
app.use('/session', sessionRouter);
app.use('/crypto', cryptoRouter);
app.use('/keys', keysRouter);

// start background session GC
sessions.startGc();

// Error fallback
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const code = err?.code || 'INTERNAL_ERROR';
    const message = err?.message || 'Unexpected error';
    res.status(500).json({ error: { code, message } });
});

app.listen(cfg.port, () => {
    // eslint-disable-next-line no-console
    console.log(`KMS listening on :${cfg.port}`);
});
