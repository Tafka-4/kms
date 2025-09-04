import crypto from 'node:crypto';

export function generateEd25519KeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { publicKey, privateKey };
}

export function sign(privateKey: crypto.KeyObject, data: Buffer): Buffer {
    return crypto.sign(null, data, privateKey);
}

export function verify(publicKey: crypto.KeyObject, data: Buffer, signature: Buffer): boolean {
    return crypto.verify(null, data, publicKey, signature);
}
