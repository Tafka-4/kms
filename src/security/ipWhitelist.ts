import { NextFunction, Request, Response } from 'express';

function ipToLong(ip: string): number | null {
    const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const parts = m.slice(1).map((n) => Number(n));
    if (parts.some((n) => n < 0 || n > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function dottedMaskToLong(mask: string): number | null {
    return ipToLong(mask);
}

function cidrMatch(ip: string, cidr: string): boolean {
    const [range, bitsStr] = cidr.split('/');
    const ipLong = ipToLong(ip);
    const rangeLong = ipToLong(range);
    if (ipLong == null || rangeLong == null) return false;
    // Support CIDR (bits) and dotted-decimal netmask
    if (bitsStr.includes('.')) {
        const maskLong = dottedMaskToLong(bitsStr);
        if (maskLong == null) return false;
        return (ipLong & maskLong) === (rangeLong & maskLong);
    } else {
        const bits = Number(bitsStr);
        if (isNaN(bits) || bits < 0 || bits > 32) return false;
        const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
        return (ipLong & mask) === (rangeLong & mask);
    }
}

function wildcardMatch(ip: string, pattern: string): boolean {
    // Only IPv4 with 4 octets, pattern octets can be '*' or numeric
    const ipParts = ip.split('.');
    const patParts = pattern.split('.');
    if (ipParts.length !== 4 || patParts.length !== 4) return false;
    for (let i = 0; i < 4; i++) {
        const p = patParts[i];
        if (p === '*') continue;
        const n = Number(p);
        const ipNum = Number(ipParts[i]);
        if (!Number.isInteger(n) || n < 0 || n > 255) return false;
        if (!Number.isInteger(ipNum) || ipNum < 0 || ipNum > 255) return false;
        if (ipNum !== n) return false;
    }
    return true;
}

function isWhitelistedIp(ip: string, whitelist: string[]): boolean {
    const normalized = ip.startsWith('::ffff:') ? ip.replace('::ffff:', '') : ip;
    for (const entry of whitelist) {
        if (!entry) continue;
        if (entry.includes('/')) {
            if (cidrMatch(normalized, entry)) return true;
        } else if (entry.includes('*')) {
            if (wildcardMatch(normalized, entry)) return true;
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
