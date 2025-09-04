import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../middleware/validate.js';
import { requireClientToken } from '../middleware/auth.js';
import { KeyStore } from '../store/keyStore.js';
import { loadConfig } from '../config.js';
import { rateLimit } from '../middleware/rateLimit.js';

const cfg = loadConfig();
const store = new KeyStore(cfg.keyStorePath);

export const keysRouter = Router();

// Apply rate limit per client token/ip for keys operations
keysRouter.use(
    rateLimit({
        windowMs: cfg.keysRateLimitWindowMs,
        max: cfg.keysRateLimitMax,
        errorMessage: 'Too many key management requests',
    })
);

keysRouter.post('/generate', requireClientToken, validateBody(z.object({})), (req, res) => {
    try {
        const { keyId, version } = store.generateKey();
        return res.status(201).json({ data: { keyId, version } });
    } catch (err) {
        return res.status(500).json({ error: { code: 'KEYS_GENERATE_FAILED', message: 'Key generation failed', details: String(err) } });
    }
});

const rotateSchema = z.object({ keyId: z.string().min(1) });
keysRouter.post('/rotate', requireClientToken, validateBody(rotateSchema), (req, res) => {
    const { keyId } = req.body as z.infer<typeof rotateSchema>;
    const out = store.rotateKey(keyId);
    if (!out) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key not found' } });
    return res.json({ data: out });
});

keysRouter.get('/:keyId', requireClientToken, (req, res) => {
    const { keyId } = req.params;
    const meta = store.getMetadata(keyId);
    if (!meta) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key not found' } });
    return res.json({ data: meta });
});
