import { NextFunction, Request, Response } from 'express';
import { loadConfig } from '../config.js';

const cfg = loadConfig();

type Bucket = { count: number; resetAt: number };

type RateLimitOpts = {
  windowMs: number;
  max: number;
  keyFn?: (req: Request) => string;
  errorMessage?: string;
};

// Create an isolated rate limiter instance (no global cross-route sharing)
export function rateLimit(opts: RateLimitOpts) {
  const buckets = new Map<string, Bucket>();
  const keyFn = opts.keyFn ?? ((req: Request) => String(req.header('X-Client-Token') || req.ip || 'unknown'));
  const errorMessage = opts.errorMessage ?? 'Too many requests';
  return (req: Request, res: Response, next: NextFunction) => {
    const key = keyFn(req);
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + opts.windowMs };
      buckets.set(key, bucket);
    }
    if (bucket.count >= opts.max) {
      const retryAfterSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      return res.status(429).json({ error: { code: 'RATE_LIMITED', message: errorMessage, details: { retryAfterSec } } });
    }
    bucket.count += 1;
    next();
  };
}

// Ensure rotate limiter persists across requests
const rotateLimiter = rateLimit({
  windowMs: cfg.rotateRateLimitWindowMs,
  max: cfg.rotateRateLimitMax,
  errorMessage: 'Too many rotate requests',
});

export function rateLimitRotate(req: Request, res: Response, next: NextFunction) {
  return rotateLimiter(req, res, next);
}
