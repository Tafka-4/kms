import { NextFunction, Request, Response } from 'express';
import { loadConfig } from '../config.js';

const cfg = loadConfig();

type Bucket = { count: number; resetAt: number };
const buckets = new Map<string, Bucket>();

export function rateLimitRotate(req: Request, res: Response, next: NextFunction) {
  const key = String(req.header('X-Client-Token') || req.ip || 'unknown');
  const now = Date.now();
  const windowMs = cfg.rotateRateLimitWindowMs;
  const max = cfg.rotateRateLimitMax;

  let bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }

  if (bucket.count >= max) {
    const retryAfterSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
    res.setHeader('Retry-After', String(retryAfterSec));
    return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many rotate requests', details: { retryAfterSec } } });
  }

  bucket.count += 1;
  next();
}
