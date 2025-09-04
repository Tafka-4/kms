import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '../middleware/validate.js';
import { requireClientToken } from '../middleware/auth.js';
import { aesGcmDecrypt, aesGcmEncrypt } from '../crypto/aes.js';
import { Algorithm } from '../types.js';

const encryptSchema = z.object({
    algorithm: z.literal('AES-256-GCM'),
    plaintext: z.string().min(1), // base64
    aad: z.string().optional(), // base64
});

const decryptSchema = z.object({
    algorithm: z.literal('AES-256-GCM'),
    ciphertext: z.string().min(1), // base64
    iv: z.string().min(1), // base64 (12 bytes)
    tag: z.string().min(1), // base64 (16 bytes)
    aad: z.string().optional(), // base64
});

export const cryptoRouter = Router();

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
