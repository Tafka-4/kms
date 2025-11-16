import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../middleware/validate.js';
import { requireClientToken } from '../middleware/auth.js';
import { KeyStore } from '../store/keyStore.js';
import { loadConfig } from '../config.js';
import { rateLimit } from '../middleware/rateLimit.js';
import { aesGcmDecrypt, aesGcmEncrypt } from '../crypto/aes.js';
import { isBase64 } from '../utils/validation.js';

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

const wrapSchema = z.object({
    keyId: z.string().min(1),
    version: z.number().int().positive(),
    plaintext: z.string().min(1).refine(isBase64, 'Invalid base64 plaintext'),
});

keysRouter.post('/wrap', requireClientToken, validateBody(wrapSchema), (req, res) => {
    const { keyId, version, plaintext } = req.body as z.infer<typeof wrapSchema>;
    const key = store.getKeyMaterial(keyId, version);
    if (!key) {
        return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key or version unavailable' } });
    }
    const { ciphertext, iv, tag } = aesGcmEncrypt(Buffer.from(plaintext, 'base64'), key);
    return res.json({
        data: {
            ciphertext: ciphertext.toString('base64'),
            iv: iv.toString('base64'),
            tag: tag.toString('base64'),
        },
    });
});

const unwrapSchema = z.object({
    keyId: z.string().min(1),
    version: z.number().int().positive(),
    ciphertext: z.string().min(1).refine(isBase64, 'Invalid base64 ciphertext'),
    iv: z
        .string()
        .min(1)
        .refine(isBase64, 'Invalid base64 IV')
        .refine((s) => Buffer.from(s, 'base64').length === 12, 'IV must be 12 bytes'),
    tag: z
        .string()
        .min(1)
        .refine(isBase64, 'Invalid base64 tag')
        .refine((s) => Buffer.from(s, 'base64').length === 16, 'Tag must be 16 bytes'),
});

keysRouter.post('/unwrap', requireClientToken, validateBody(unwrapSchema), (req, res) => {
    const { keyId, version, ciphertext, iv, tag } = req.body as z.infer<typeof unwrapSchema>;
    const key = store.getKeyMaterial(keyId, version);
    if (!key) {
        return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Key or version unavailable' } });
    }
    try {
        const plaintext = aesGcmDecrypt(Buffer.from(ciphertext, 'base64'), Buffer.from(iv, 'base64'), Buffer.from(tag, 'base64'), key);
        return res.json({ data: { plaintext: plaintext.toString('base64') } });
    } catch (error) {
        return res.status(400).json({ error: { code: 'DECRYPT_FAILED', message: 'Unable to unwrap payload', details: String(error) } });
    }
});
