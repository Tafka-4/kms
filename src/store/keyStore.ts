import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { KeyMetadata, StoredKeyRecord, StoredKeyVersion } from '../types.js';

const STORE_FILE = 'keys.json';
const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export class KeyStore {
    private filePath: string;
    private cache: Map<string, StoredKeyRecord> = new Map();

    constructor(private baseDir: string) {
        this.filePath = path.join(baseDir, STORE_FILE);
        this.load();
    }

    private load() {
        if (!fs.existsSync(this.filePath)) {
            this.persist();
            return;
        }
        try {
            const raw = fs.readFileSync(this.filePath, 'utf8');
            const arr: StoredKeyRecord[] = JSON.parse(raw);
            for (const rec of arr) this.cache.set(rec.keyId, rec);
        } catch {
            this.cache.clear();
            this.persist();
        }
    }

    private persist() {
        const arr = Array.from(this.cache.values());
        const tmp = `${this.filePath}.tmp-${process.pid}-${Date.now()}`;
        fs.writeFileSync(tmp, JSON.stringify(arr, null, 2));
        fs.renameSync(tmp, this.filePath);
    }

    generateKey(): { keyId: string; version: number; wrapped?: never } {
        const keyId = crypto.randomUUID();
        const material = crypto.randomBytes(32).toString('base64');
        const createdAt = Date.now();
        const version = 1;
        const rec: StoredKeyRecord = {
            keyId,
            createdAt,
            versions: [
                {
                    version,
                    createdAt,
                    status: 'active',
                    materialB64: material,
                },
            ],
        };
        this.cache.set(keyId, rec);
        this.persist();
        return { keyId, version };
    }

    rotateKey(keyId: string): { keyId: string; version: number } | null {
        const rec = this.cache.get(keyId);
        if (!rec) return null;
        const now = Date.now();
        // deprecate current active
        for (const v of rec.versions) {
            if (v.status === 'active') {
                v.status = 'deprecated';
                v.expiresAt = now + GRACE_PERIOD_MS;
            }
        }
        const newVersion: StoredKeyVersion = {
            version: Math.max(...rec.versions.map((v) => v.version)) + 1,
            createdAt: now,
            status: 'active',
            materialB64: crypto.randomBytes(32).toString('base64'),
        };
        rec.versions.push(newVersion);
        this.persist();
        return { keyId, version: newVersion.version };
    }

    getMetadata(keyId: string): KeyMetadata | null {
        const rec = this.cache.get(keyId);
        if (!rec) return null;
        return {
            keyId: rec.keyId,
            createdAt: rec.createdAt,
            versions: rec.versions.map(({ materialB64: _m, ...meta }) => meta),
        };
    }
}
