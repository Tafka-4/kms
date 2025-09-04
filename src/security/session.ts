import crypto from 'node:crypto';
import { SessionRecord } from '../types.js';
import { loadConfig } from '../config.js';

const cfg = loadConfig();
const DEFAULT_TTL_MS = cfg.sessionTtlMs; // configurable

class SessionStore {
    private byToken = new Map<string, SessionRecord>();
    private bySessionId = new Map<string, SessionRecord>();
    private gcTimer?: NodeJS.Timeout;

    createPending(sessionId?: string): string {
        return sessionId ?? crypto.randomUUID();
    }

    upsert(sessionId: string, clientToken: string, key: Buffer, ttlMs: number = DEFAULT_TTL_MS): SessionRecord {
        const now = Date.now();
        const record: SessionRecord = {
            sessionId,
            clientToken,
            key,
            createdAt: now,
            expiresAt: now + ttlMs,
        };
        this.byToken.set(clientToken, record);
        this.bySessionId.set(sessionId, record);
        return record;
    }

    getByToken(clientToken: string): SessionRecord | undefined {
        const rec = this.byToken.get(clientToken);
        if (rec && rec.expiresAt > Date.now()) return rec;
        if (rec) this.delete(rec);
        return undefined;
    }

    getBySessionId(sessionId: string): SessionRecord | undefined {
        const rec = this.bySessionId.get(sessionId);
        if (rec && rec.expiresAt > Date.now()) return rec;
        if (rec) this.delete(rec);
        return undefined;
    }

    delete(rec: SessionRecord) {
        this.byToken.delete(rec.clientToken);
        this.bySessionId.delete(rec.sessionId);
    }

    rotateToken(oldToken: string): { newToken: string; expiresAt: number } | undefined {
        const rec = this.getByToken(oldToken);
        if (!rec) return undefined;
        const newToken = SessionStore.generateRandomToken();
        // remap token
        this.byToken.delete(rec.clientToken);
        rec.clientToken = newToken;
        // sliding expiration on rotate
        if (cfg.sessionSliding) {
            const now = Date.now();
            rec.expiresAt = now + DEFAULT_TTL_MS;
        }
        this.byToken.set(newToken, rec);
        return { newToken, expiresAt: rec.expiresAt };
    }

    private static generateRandomToken(): string {
        // 32 bytes ~ 256 bits of entropy; URL-safe
        const core = crypto.randomBytes(32).toString('base64url');
        return cfg.tokenPrefix ? `${cfg.tokenPrefix}_${core}` : core;
    }

    replaceToken(oldToken: string, desiredNewToken: string): { newToken: string; expiresAt: number } | undefined {
        const rec = this.getByToken(oldToken);
        if (!rec) return undefined;
        if (!SessionStore.isValidToken(desiredNewToken)) {
            throw new Error('TOKEN_INVALID');
        }
        if (this.byToken.has(desiredNewToken)) {
            throw new Error('TOKEN_CONFLICT');
        }
        this.byToken.delete(rec.clientToken);
        rec.clientToken = desiredNewToken;
        if (cfg.sessionSliding) {
            const now = Date.now();
            rec.expiresAt = now + DEFAULT_TTL_MS;
        }
        this.byToken.set(desiredNewToken, rec);
        return { newToken: desiredNewToken, expiresAt: rec.expiresAt };
    }

    private static isValidToken(token: string): boolean {
        // optional prefix + base64url body (>=128 bits)
        const body = cfg.tokenPrefix ? token.replace(new RegExp(`^${cfg.tokenPrefix}_`), '') : token;
        return /^[A-Za-z0-9_-]{22,}$/.test(body);
    }

    startGc() {
        if (this.gcTimer) return;
        const period = Math.max(10_000, Math.floor(DEFAULT_TTL_MS / 3));
        this.gcTimer = setInterval(() => this.gcOnce(), period);
        if ((this.gcTimer as any).unref) (this.gcTimer as any).unref();
    }

    private gcOnce() {
        const now = Date.now();
        for (const rec of Array.from(this.byToken.values())) {
            if (rec.expiresAt <= now) this.delete(rec);
        }
    }
}

export const sessions = new SessionStore();
