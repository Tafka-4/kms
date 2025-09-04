import { NextFunction, Request, Response } from 'express';
import { sessions } from '../security/session.js';
import { loadConfig } from '../config.js';

export function requireClientToken(req: Request, res: Response, next: NextFunction) {
    const token = String(req.header('X-Client-Token') || '');
    if (!token) {
        return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Missing X-Client-Token' } });
    }
    // basic format validation
    if (!/^[A-Za-z0-9_-]{22,}$/.test(token)) {
        return res.status(400).json({ error: { code: 'TOKEN_INVALID', message: 'Invalid token format' } });
    }
    const session = sessions.getByToken(token);
    if (!session) {
        return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'No active session for token' } });
    }
    // attach for downstream
    (req as any).session = session;
    next();
}
