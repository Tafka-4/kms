export type ErrorResponse = {
    error: { code: string; message: string; details?: unknown };
};

export type Success<T> = { data: T };

export type Algorithm = 'AES-256-GCM';

export type SessionRecord = {
    sessionId: string;
    clientToken: string;
    key: Buffer; // AES-256 key
    createdAt: number;
    expiresAt: number;
};

export type KeyVersionStatus = 'active' | 'deprecated';

export interface KeyVersionMeta {
    version: number;
    createdAt: number;
    status: KeyVersionStatus;
    expiresAt?: number; // if deprecated, optional grace period end
}

export interface KeyMetadata {
    keyId: string;
    createdAt: number;
    versions: KeyVersionMeta[];
}

export interface StoredKeyVersion extends KeyVersionMeta {
    materialB64: string; // base64 key material; demo purpose only
}

export interface StoredKeyRecord {
    keyId: string;
    createdAt: number;
    versions: StoredKeyVersion[];
}
