import crypto from 'node:crypto';

export type AesGcmEncryptResult = {
    iv: Buffer;
    tag: Buffer;
    ciphertext: Buffer;
};

export function aesGcmEncrypt(plaintext: Buffer, key: Buffer, aad?: Buffer): AesGcmEncryptResult {
    if (key.length !== 32) throw new Error('AES-256-GCM requires 32-byte key');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (aad) cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { iv, tag, ciphertext };
}

export function aesGcmDecrypt(ciphertext: Buffer, iv: Buffer, tag: Buffer, key: Buffer, aad?: Buffer): Buffer {
    if (key.length !== 32) throw new Error('AES-256-GCM requires 32-byte key');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    if (aad) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
