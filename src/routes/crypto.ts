import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../middleware/validate.js';
import { requireClientToken } from '../middleware/auth.js';
import { aesGcmDecrypt, aesGcmEncrypt } from '../crypto/aes.js';
import { Algorithm } from '../types.js';
import { isBase64 } from '../utils/validation.js';
import { rateLimit } from '../middleware/rateLimit.js';
import { loadConfig } from '../config.js';

const cfg = loadConfig();

const encryptSchema = z.object({
    algorithm: z.literal('AES-256-GCM'),
    plaintext: z
        .string()
        .min(1)
        .max(131072, 'Plaintext too large')
        .refine(isBase64, 'Invalid base64 plaintext'),
    aad: z
        .string()
        .max(8192, 'AAD too large')
        .refine((v) => isBase64(v), 'Invalid base64 AAD')
        .optional(),
});

const decryptSchema = z.object({
    algorithm: z.literal('AES-256-GCM'),
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
    aad: z
        .string()
        .max(8192, 'AAD too large')
        .refine((v) => isBase64(v), 'Invalid base64 AAD')
        .optional(),
});

export const cryptoRouter = Router();

// Apply rate limit per client token/ip for crypto operations
cryptoRouter.use(
    rateLimit({
        windowMs: cfg.cryptoRateLimitWindowMs,
        max: cfg.cryptoRateLimitMax,
        errorMessage: 'Too many crypto requests',
    })
);

cryptoRouter.post('/encrypt', requireClientToken, validateBody(encryptSchema), (req, res) => {
    const session = (req as any).session as { key: Buffer };
    const { plaintext, aad } = req.body as z.infer<typeof encryptSchema> & { algorithm: Algorithm };
    try {
        const pt = Buffer.from(plaintext, 'base64');
        const aadBuf = aad ? Buffer.from(aad, 'base64') : undefined;
        const { ciphertext, iv, tag } = aesGcmEncrypt(pt, session.key, aadBuf);
        return res.json({
            data: {
                ciphertext: ciphertext.toString('base64'),
                iv: iv.toString('base64'),
                tag: tag.toString('base64'),
            },
        });
    } catch (err) {
        return res.status(400).json({ error: { code: 'ENCRYPT_FAILED', message: 'Encryption failed', details: String(err) } });
    }
});

cryptoRouter.post('/decrypt', requireClientToken, validateBody(decryptSchema), (req, res) => {
    const session = (req as any).session as { key: Buffer };
    const { ciphertext, iv, tag, aad } = req.body as z.infer<typeof decryptSchema> & { algorithm: Algorithm };
    try {
        const pt = aesGcmDecrypt(
            Buffer.from(ciphertext, 'base64'),
            Buffer.from(iv, 'base64'),
            Buffer.from(tag, 'base64'),
            session.key,
            aad ? Buffer.from(aad, 'base64') : undefined
        );
        return res.json({ data: { plaintext: pt.toString('base64') } });
    } catch (err) {
        return res.status(400).json({ error: { code: 'DECRYPT_FAILED', message: 'Decryption failed', details: String(err) } });
    }
});
