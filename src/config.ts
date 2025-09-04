import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_PORT = 3000;
const DEFAULT_WHITELIST = '100.64.0.9';
const DEFAULT_KEY_STORE = './data/keys';

export type AppConfig = {
    port: number;
    whitelist: string[];
    keyStorePath: string;
    nodeEnv: string | undefined;
    sessionTtlMs: number;
    sessionSliding: boolean;
    rotateRateLimitWindowMs: number;
    rotateRateLimitMax: number;
    tokenPrefix?: string;
};

export function loadConfig(): AppConfig {
    const port = Number(process.env.KMS_PORT ?? DEFAULT_PORT);
    const whitelistCsv = (process.env.KMS_WHITELIST ?? DEFAULT_WHITELIST).trim();
    const whitelist = whitelistCsv.split(',').map((s) => s.trim()).filter(Boolean);
    const keyStorePath = process.env.KEY_STORE_PATH ?? DEFAULT_KEY_STORE;
    const nodeEnv = process.env.NODE_ENV;
    const sessionTtlMs = Number(process.env.KMS_SESSION_TTL_MS ?? 15 * 60 * 1000);
    const sessionSliding = String(process.env.KMS_SESSION_SLIDING ?? 'true') === 'true';
    const rotateRateLimitWindowMs = Number(process.env.KMS_ROTATE_WINDOW_MS ?? 10_000);
    const rotateRateLimitMax = Number(process.env.KMS_ROTATE_MAX ?? 5);
    const tokenPrefix = process.env.KMS_TOKEN_PREFIX?.trim() || undefined;

    ensureKeyStorePath(keyStorePath);

    return { port, whitelist, keyStorePath, nodeEnv, sessionTtlMs, sessionSliding, rotateRateLimitWindowMs, rotateRateLimitMax, tokenPrefix };
}

function ensureKeyStorePath(dir: string) {
    try {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        // test write permissions via temp file
        const testFile = path.join(dir, `.write-test-${Date.now()}`);
        fs.writeFileSync(testFile, 'ok');
        fs.rmSync(testFile);
    } catch (err) {
        // eslint-disable-next-line no-console
        console.error(
            JSON.stringify({ error: { code: 'CONFIG_KEY_STORE_PATH', message: `KEY_STORE_PATH not writeable: ${dir}`, details: String(err) } }, null, 2)
        );
        process.exit(1);
    }
}
