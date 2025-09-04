import { NextFunction, Request, Response } from 'express';
import { loadConfig } from '../config.js';

const cfg = loadConfig();

export function isValidClientToken(token: string): boolean {
  if (!token || typeof token !== 'string') return false;
  let body = token;
  if (cfg.tokenPrefix && token.startsWith(cfg.tokenPrefix + '_')) {
    body = token.slice(cfg.tokenPrefix.length + 1);
  }
  return /^[A-Za-z0-9_-]{22,}$/.test(body);
}

export function requireValidClientTokenHeader(req: Request, res: Response, next: NextFunction) {
  const token = String(req.header('X-Client-Token') || '');
  if (!token) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Missing X-Client-Token' } });
  }
  if (!isValidClientToken(token)) {
    return res.status(400).json({ error: { code: 'TOKEN_INVALID', message: 'Invalid token format' } });
  }
  next();
}

export function getSafeRequestId(input?: string | string[]): string | undefined {
  const val = Array.isArray(input) ? input[0] : input;
  if (!val) return undefined;
  const trimmed = String(val).trim();
  if (trimmed.length > 128) return undefined;
  const uuidV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const b64url = /^[A-Za-z0-9_-]{8,64}$/;
  if (uuidV4.test(trimmed) || b64url.test(trimmed)) return trimmed;
  return undefined;
}

