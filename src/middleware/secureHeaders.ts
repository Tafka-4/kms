import { NextFunction, Request, Response } from 'express';

export function secureHeaders() {
    return (req: Request, res: Response, next: NextFunction) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
        const xfproto = (req.headers['x-forwarded-proto'] as string) || '';
        if (process.env.NODE_ENV === 'production' && xfproto === 'https') {
            res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        }
        next();
    };
}

