// E2E client: handshake + file encrypt/decrypt via KMS
// Usage: node client/testE2E.mjs <inFile> <cipherOutJson> <roundtripOutFile>
// Env: BASE_URL (default http://localhost:3000), TOKEN (default demo-client-token)

import fs from 'node:fs';
import crypto from 'node:crypto';

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const TOKEN = process.env.TOKEN || crypto.randomBytes(16).toString('base64url');
const ROTATE_INTERVAL_MS = Number(process.env.ROTATE_INTERVAL_MS || 0); // 0=disabled
const NEGATIVE_TESTS = String(process.env.NEGATIVE_TESTS || 'false') === 'true';

function b64(buf) {
    return Buffer.from(buf).toString('base64');
}

async function httpJson(url, opts = {}) {
    const res = await fetch(url, opts);
    const body = await res.text();
    let json;
    try { json = JSON.parse(body); } catch { json = { raw: body }; }
    if (!res.ok) {
        throw new Error(`${res.status} ${res.statusText}: ${body}`);
    }
    return json;
}

async function waitForServer(url, { retries = 40, intervalMs = 500 } = {}) {
    const healthUrl = url.replace(/\/$/, '') + '/health';
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            const res = await fetch(healthUrl);
            if (res.ok) {
                console.log(`[warmup] server is ready at ${healthUrl}`);
                return true;
            }
            console.log(`[warmup] attempt ${attempt}/${retries} -> ${res.status}`);
        } catch (e) {
            console.log(`[warmup] attempt ${attempt}/${retries} failed: ${(e && e.message) || e}`);
        }
        await new Promise((r) => setTimeout(r, intervalMs));
    }
    throw new Error(`Server not reachable at ${healthUrl} after ${retries} attempts`);
}

async function main() {
    const [inFile, cipherOut, roundtripOut] = process.argv.slice(2);
    if (!inFile || !cipherOut || !roundtripOut) {
        console.error('Usage: node client/testE2E.mjs <inFile> <cipherOutJson> <roundtripOutFile>');
        process.exit(2);
    }

    console.log(`[env] BASE_URL=${BASE} TOKEN(len)=${TOKEN.length}`);

    // 0) wait for server
    await waitForServer(BASE);

    // 1) session init
    console.log('[step] GET /session/init');
    const init = await httpJson(`${BASE}/session/init`);
    const { sessionId, rsaPublicKeyPem } = init.data;

    // 2) key exchange
    const sessionKey = crypto.randomBytes(32);
    const publicKey = crypto.createPublicKey(rsaPublicKeyPem);
    const wrapped = crypto.publicEncrypt(
        { key: publicKey, oaepHash: 'sha256', padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
        sessionKey
    );
    console.log('[step] POST /session/key-exchange');
    await httpJson(`${BASE}/session/key-exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Client-Token': TOKEN },
        body: JSON.stringify({ sessionId, wrappedKey: b64(wrapped) }),
    });

    // rotate token immediately to a fresh random one
    const desiredNewToken = crypto.randomBytes(32).toString('base64url');
    console.log('[step] POST /session/rotate-token');
    const rot = await httpJson(`${BASE}/session/rotate-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Client-Token': TOKEN },
        body: JSON.stringify({ token: desiredNewToken }),
    });
    let activeToken = rot.data?.newToken || desiredNewToken;

    // 3) encrypt file
    const inputBytes = fs.readFileSync(inFile);
    console.log('[step] POST /crypto/encrypt');
    const enc = await httpJson(`${BASE}/crypto/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Client-Token': activeToken },
        body: JSON.stringify({ algorithm: 'AES-256-GCM', plaintext: b64(inputBytes) }),
    });
    fs.writeFileSync(cipherOut, JSON.stringify(enc.data, null, 2));

    // 4) decrypt
    console.log('[step] POST /crypto/decrypt');
    const dec = await httpJson(`${BASE}/crypto/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Client-Token': activeToken },
        body: JSON.stringify({ algorithm: 'AES-256-GCM', ...enc.data }),
    });
    const outBytes = Buffer.from(dec.data.plaintext, 'base64');
    fs.writeFileSync(roundtripOut, outBytes);

    // 5) verify
    const equal = Buffer.compare(inputBytes, outBytes) === 0;
    if (!equal) {
        console.error('E2E FAILED: round-trip bytes mismatch');
        process.exit(1);
    }
    console.log('E2E OK: bytes match');

    // Optional: periodic rotation demo
    if (ROTATE_INTERVAL_MS > 0) {
        console.log(`[rotate] enabling periodic rotation every ${ROTATE_INTERVAL_MS}ms`);
        const timer = setInterval(async () => {
            try {
                const desired = crypto.randomBytes(32).toString('base64url');
                const r = await httpJson(`${BASE}/session/rotate-token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Client-Token': activeToken },
                    body: JSON.stringify({ token: desired }),
                });
                activeToken = r.data?.newToken || desired;
                console.log(`[rotate] rotated, expiresAt=${r.data?.expiresAt}`);
            } catch (e) {
                console.log(`[rotate] failed: ${(e && e.message) || e}`);
            }
        }, ROTATE_INTERVAL_MS);
        // run one extra encrypt/decrypt after first rotation just to show it works
        await new Promise((r) => setTimeout(r, ROTATE_INTERVAL_MS + 200));
        console.log('[step] POST /crypto/encrypt after rotation');
        const enc2 = await httpJson(`${BASE}/crypto/encrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Client-Token': activeToken },
            body: JSON.stringify({ algorithm: 'AES-256-GCM', plaintext: b64(inputBytes) }),
        });
        console.log('[step] POST /crypto/decrypt after rotation');
        await httpJson(`${BASE}/crypto/decrypt`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Client-Token': activeToken },
            body: JSON.stringify({ algorithm: 'AES-256-GCM', ...enc2.data }),
        });
        clearInterval(timer);
        console.log('[rotate] periodic rotation demo complete');
    }

    if (NEGATIVE_TESTS) {
        console.log('[neg] run negative tests');
        // 401 with wrong token
        let failed401 = false;
        try {
            await httpJson(`${BASE}/crypto/encrypt`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Client-Token': 'invalid-token' },
                body: JSON.stringify({ algorithm: 'AES-256-GCM', plaintext: b64(Buffer.from('x')) }),
            });
        } catch (e) {
            failed401 = /401/.test(String(e));
        }
        console.log(`[neg] invalid token -> 401: ${failed401}`);
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});

