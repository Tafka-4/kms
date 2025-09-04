import { NextFunction, Request, Response } from 'express';
import crypto from 'node:crypto';
import { getSafeRequestId } from './headers.js';

export function requestLogger(req: Request, res: Response, next: NextFunction) {
    const start = Date.now();
    const method = req.method;
    const url = req.originalUrl || req.url;
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip;
    const incomingId = req.headers['x-request-id'];
    const safe = getSafeRequestId(incomingId as any);
    const requestId = safe || crypto.randomUUID();
    (req as any).requestId = requestId;
    res.setHeader('X-Request-Id', requestId);
    res.on('finish', () => {
        const ms = Date.now() - start;
        // eslint-disable-next-line no-console
        console.log(JSON.stringify({ level: 'info', requestId, method, url, status: res.statusCode, ms, ip }));
    });
    next();
}


