import { canon } from './util.js';

/** Small JSON-Schema subset validator. Returns an error string or null. */
export function validateSchema(v, s, path = '$') {
  if (!s || typeof s !== 'object') return null;
  if (Array.isArray(s.enum) && !s.enum.some((e) => canon(e) === canon(v))) return `${path}: not in enum`;
  const t = s.type;
  if (t) {
    const ok = t === 'object' ? v && typeof v === 'object' && !Array.isArray(v)
      : t === 'array' ? Array.isArray(v)
      : t === 'integer' ? Number.isInteger(v)
      : t === 'number' ? typeof v === 'number' && Number.isFinite(v)
      : t === 'string' ? typeof v === 'string'
      : t === 'boolean' ? typeof v === 'boolean' : true;
    if (!ok) return `${path}: expected ${t}`;
  }
  if (typeof v === 'string') {
    if (s.minLength != null && v.length < s.minLength) return `${path}: too short`;
    if (s.maxLength != null && v.length > s.maxLength) return `${path}: too long`;
    if (s.pattern) { try { if (!new RegExp(s.pattern).test(v)) return `${path}: pattern mismatch`; } catch {} }
  }
  if (typeof v === 'number') {
    if (s.minimum != null && v < s.minimum) return `${path}: below minimum`;
    if (s.maximum != null && v > s.maximum) return `${path}: above maximum`;
  }
  if (v && typeof v === 'object' && !Array.isArray(v) && (t === 'object' || s.properties)) {
    for (const r of s.required || []) if (!(r in v)) return `${path}: missing ${r}`;
    const props = s.properties || {};
    for (const k of Object.keys(v)) {
      if (props[k]) { const e = validateSchema(v[k], props[k], `${path}.${k}`); if (e) return e; }
      else if (s.additionalProperties === false) return `${path}: unexpected ${k}`;
    }
  }
  if (Array.isArray(v) && s.items) {
    for (let i = 0; i < v.length; i++) { const e = validateSchema(v[i], s.items, `${path}[${i}]`); if (e) return e; }
  }
  return null;
}
