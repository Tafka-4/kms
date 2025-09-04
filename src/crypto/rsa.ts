import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export type RsaKeyPaths = { privateKeyPath: string; publicKeyPath: string };

export function getRsaKeyPaths(storeDir: string): RsaKeyPaths {
    return {
        privateKeyPath: path.join(storeDir, 'rsa_private.pem'),
        publicKeyPath: path.join(storeDir, 'rsa_public.pem'),
    };
}

export function loadOrCreateRsaKeyPair(storeDir: string) {
    const { privateKeyPath, publicKeyPath } = getRsaKeyPaths(storeDir);
    if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
        const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
        const publicKeyPem = fs.readFileSync(publicKeyPath, 'utf8');
        return {
            privateKey: crypto.createPrivateKey(privateKeyPem),
            publicKey: crypto.createPublicKey(publicKeyPem),
            publicKeyPem,
        };
    }
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicExponent: 0x10001,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });
    return {
        privateKey: crypto.createPrivateKey(privateKey),
        publicKey: crypto.createPublicKey(publicKey),
        publicKeyPem: publicKey,
    };
}

export function rsaOaepUnwrap(privateKey: crypto.KeyObject, wrappedKeyB64: string, label?: Buffer): Buffer {
    const wrapped = Buffer.from(wrappedKeyB64, 'base64');
    return crypto.privateDecrypt(
        {
            key: privateKey,
            oaepHash: 'sha256',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepLabel: label,
        },
        wrapped
    );
}

export function rsaOaepWrap(publicKey: crypto.KeyObject, keyData: Buffer, label?: Buffer): string {
    const wrapped = crypto.publicEncrypt(
        {
            key: publicKey,
            oaepHash: 'sha256',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepLabel: label,
        },
        keyData
    );
    return wrapped.toString('base64');
}
