export function isBase64(input: string): boolean {
  if (input.length === 0) return false;
  // Reject if not plausible base64 (allow with/without padding)
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(input)) return false;
  try {
    const buf = Buffer.from(input, 'base64');
    // Ensure decoding round-trips (avoids ignoring non-base64 chars)
    return buf.length > 0 && buf.toString('base64').replace(/=+$/, '') === input.replace(/=+$/, '');
  } catch {
    return false;
  }
}

export function isBase64Url(input: string): boolean {
  if (input.length === 0) return false;
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return false;
  try {
    // Convert to standard base64 for round-trip check
    const std = input.replace(/-/g, '+').replace(/_/g, '/');
    const buf = Buffer.from(std, 'base64');
    const rt = buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return buf.length > 0 && rt === input.replace(/=+$/, '');
  } catch {
    return false;
  }
}

