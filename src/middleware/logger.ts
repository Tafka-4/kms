import { NextFunction, Request, Response } from 'express';

export function requestLogger(req: Request, res: Response, next: NextFunction) {
    const start = Date.now();
    const method = req.method;
    const url = req.originalUrl || req.url;
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip;
    res.on('finish', () => {
        const ms = Date.now() - start;
        // eslint-disable-next-line no-console
        console.log(JSON.stringify({ level: 'info', method, url, status: res.statusCode, ms, ip }));
    });
    next();
}

