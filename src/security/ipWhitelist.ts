import { NextFunction, Request, Response } from 'express';

function ipToLong(ip: string): number | null {
    const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const parts = m.slice(1).map((n) => Number(n));
    if (parts.some((n) => n < 0 || n > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function cidrMatch(ip: string, cidr: string): boolean {
    const [range, bitsStr] = cidr.split('/');
    const bits = Number(bitsStr);
    const ipLong = ipToLong(ip);
    const rangeLong = ipToLong(range);
    if (ipLong == null || rangeLong == null || isNaN(bits)) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipLong & mask) === (rangeLong & mask);
}

function isWhitelistedIp(ip: string, whitelist: string[]): boolean {
    const normalized = ip.startsWith('::ffff:') ? ip.replace('::ffff:', '') : ip;
    for (const entry of whitelist) {
        if (entry.includes('/')) {
            if (cidrMatch(normalized, entry)) return true;
        } else if (normalized === entry) {
            return true;
        }
    }
    return false;
}

export function ipWhitelist(whitelist: string[]) {
    return (req: Request, res: Response, next: NextFunction) => {
        const clientIp = req.ip || (req.connection as any).remoteAddress || '';
        if (!isWhitelistedIp(clientIp, whitelist)) {
            return res.status(403).json({
                error: { code: 'FORBIDDEN_IP', message: 'IP not whitelisted' },
            });
        }
        next();
    };
}
