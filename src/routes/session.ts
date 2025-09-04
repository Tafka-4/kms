import { Router } from 'express';
import { z } from 'zod';
import { sessions } from '../security/session.js';
import { loadOrCreateRsaKeyPair } from '../crypto/rsa.js';
import { validateBody } from '../middleware/validate.js';
import { loadConfig } from '../config.js';
import { rsaOaepUnwrap } from '../crypto/rsa.js';
import { rateLimitRotate } from '../middleware/rateLimit.js';

const cfg = loadConfig();
const { privateKey, publicKeyPem } = loadOrCreateRsaKeyPair(cfg.keyStorePath);

export const sessionRouter = Router();

sessionRouter.get('/init', (req, res) => {
    const sessionId = sessions.createPending();
    res.json({ data: { sessionId, rsaPublicKeyPem: publicKeyPem } });
});

const keyExchangeSchema = z.object({
    sessionId: z.string().min(1),
    wrappedKey: z.string().min(1), // base64
});

sessionRouter.post('/key-exchange', validateBody(keyExchangeSchema), (req, res) => {
    const token = String(req.header('X-Client-Token') || '');
    if (!token) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Missing X-Client-Token' } });
    const { sessionId, wrappedKey } = req.body as z.infer<typeof keyExchangeSchema>;
    try {
        const key = rsaOaepUnwrap(privateKey, wrappedKey);
        if (key.length !== 32) throw new Error('Session key must be 32 bytes');
        const rec = sessions.upsert(sessionId, token, key);
        // eslint-disable-next-line no-console
        console.log(JSON.stringify({ level: 'info', event: 'key_exchange', sessionId: rec.sessionId, expiresAt: rec.expiresAt }));
        return res.json({ data: { sessionId: rec.sessionId, expiresAt: rec.expiresAt } });
    } catch (err) {
        return res.status(400).json({ error: { code: 'KEY_EXCHANGE_FAILED', message: 'Unable to unwrap session key', details: String(err) } });
    }
});

const rotateSchema = z.object({ token: z.string().min(1).optional() });
sessionRouter.post('/rotate-token', rateLimitRotate, validateBody(rotateSchema), (req, res) => {
    const oldToken = String(req.header('X-Client-Token') || '');
    if (!oldToken) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Missing X-Client-Token' } });
    const { token } = req.body as z.infer<typeof rotateSchema>;
    try {
        const result = token
            ? sessions.replaceToken(oldToken, token)
            : sessions.rotateToken(oldToken);
        // eslint-disable-next-line no-console
        console.log(JSON.stringify({ level: 'info', event: 'token_rotate', expiresAt: result?.expiresAt }));
        if (!result) return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'No active session for token' } });
        return res.json({ data: result });
    } catch (e) {
        if ((e as Error).message === 'TOKEN_CONFLICT') {
            return res.status(409).json({ error: { code: 'TOKEN_CONFLICT', message: 'Desired token already in use' } });
        }
        if ((e as Error).message === 'TOKEN_INVALID') {
            return res.status(400).json({ error: { code: 'TOKEN_INVALID', message: 'Invalid token format' } });
        }
        return res.status(500).json({ error: { code: 'ROTATE_FAILED', message: 'Token rotation failed', details: String(e) } });
    }
});
