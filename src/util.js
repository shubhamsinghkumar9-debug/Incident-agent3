import crypto from 'node:crypto';

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
export const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');
export const newId = (prefix) => `${prefix}_${hex(6)}`; // always >= 8 chars

/** Recursively key-sorted compact JSON. */
export function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort()
      .map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

let last = 0n;
/** Strictly increasing unix-nano timestamps (as decimal strings). */
export function nowNs() {
  let t = BigInt(Date.now()) * 1000000n;
  if (t <= last) t = last + 1000n;
  last = t;
  return t.toString();
}

const TP = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
export function parseTraceparent(h, tracestate) {
  if (typeof h !== 'string') return null;
  const m = TP.exec(h.trim());
  if (!m) return null;
  if (/^0+$/.test(m[1]) || /^0+$/.test(m[2])) return null;
  const ts = typeof tracestate === 'string' && tracestate.trim() ? tracestate.trim() : null;
  return { traceId: m[1], spanId: m[2], tracestate: ts };
}

export class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
