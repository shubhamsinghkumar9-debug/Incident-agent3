import http from 'node:http';
import * as store from './store.js';
import * as planner from './planner.js';
import { createRun, applyReceipt } from './machine.js';
import { view } from './telemetry.js';
import { sha256, canon, nowNs, parseTraceparent, HttpError } from './util.js';

const PROFILE = 'ga5-incident-agent/v2';
const MAX_BODY = 8 * 1024 * 1024;
const inflight = new Map();

function send(res, status, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(s), 'cache-control': 'no-store' });
  res.end(s);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > MAX_BODY) { reject(new HttpError(413, 'too_large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new HttpError(400, 'invalid_json')); } });
    req.on('error', () => reject(new HttpError(400, 'read_error')));
  });
}

const isStr = (x, max = 512) => typeof x === 'string' && x.length > 0 && x.length <= max;
function validCreate(b) {
  if (!isStr(b.runId, 256) || !isStr(b.agentName) || !isStr(b.publicMarker)) return false;
  const i = b.incident;
  if (!i || typeof i !== 'object' || typeof i.transcript !== 'string' || !Array.isArray(i.allowedRootCauses) ||
      !i.allowedRootCauses.length || !i.allowedRootCauses.every((x) => typeof x === 'string')) return false;
  if (!Array.isArray(b.toolCatalog) || !b.toolCatalog.every((t) => t && isStr(t.name))) return false;
  const p = b.policy;
  if (!p || !Array.isArray(p.effectTools) || !Array.isArray(p.approvalRequiredFor)) return false;
  if (p.maximumDiagnostics !== undefined && !Number.isInteger(p.maximumDiagnostics)) return false;
  if (b.sensitive !== undefined && (typeof b.sensitive !== 'object' || b.sensitive === null)) return false;
  return true;
}

function collectSecrets(b) {
  const out = new Set();
  const walk = (v) => { if (typeof v === 'string') { if (v.length >= 4) out.add(v); } else if (v && typeof v === 'object') Object.values(v).forEach(walk); };
  walk(b.sensitive);
  for (const s of b.policy.doNotExport || []) if (typeof s === 'string' && s.length >= 8) out.add(s);
  return [...out];
}

async function handleCreate(req, res) {
  const t0 = nowNs();
  const body = await readJson(req);
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'invalid_body');
  if (body.profile !== PROFILE) throw new HttpError(400, 'unsupported_profile');
  if (!validCreate(body)) throw new HttpError(422, 'invalid_request');
  const reqHash = sha256(canon(body));
  const check = () => {
    const ex = store.get(body.runId);
    if (!ex) return null;
    if (ex.reqHash !== reqHash) throw new HttpError(409, 'run_conflict');
    return send(res, 200, view(ex)), true;
  };
  if (check()) return;
  if (inflight.has(body.runId)) { try { await inflight.get(body.runId); } catch {} if (check()) return; throw new HttpError(503, 'planner_unavailable'); }
  const job = (async () => {
    const incoming = parseTraceparent(req.headers['traceparent'], req.headers['tracestate']);
    const { plan, modelStart, modelEnd } = await planner.plan(body, { now: nowNs });
    const st = createRun({ body, reqHash, incoming, planned: plan, model: planner.MODEL, t0, modelStart, modelEnd, secrets: collectSecrets(body) });
    store.save(st); // persist BEFORE responding
  })();
  inflight.set(body.runId, job);
  try { await job; } catch (e) { if (e instanceof HttpError) throw e; console.error('planner error:', e.message); throw new HttpError(503, 'planner_unavailable'); }
  finally { inflight.delete(body.runId); }
  send(res, 200, view(store.get(body.runId)));
}

async function handleReceipt(req, res, runId) {
  const st = store.get(runId);
  const body = await readJson(req);
  if (!st) throw new HttpError(404, 'run_not_found');
  if (!body || typeof body !== 'object' || Array.isArray(body) || !isStr(body.receiptId, 256)) throw new HttpError(422, 'invalid_receipt');
  const h = sha256(canon(body));
  const prior = st.receipts[body.receiptId];
  if (prior) { if (prior !== h) throw new HttpError(409, 'receipt_conflict'); return send(res, 200, view(st)); }
  const c = structuredClone(st);
  applyReceipt(c, body);
  c.receipts[body.receiptId] = h;
  store.save(c);
  send(res, 200, view(c));
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname.replace(/\/+$/, '') || '/';
    let m;
    if (req.method === 'GET' && (p === '/' || p === '/healthz')) return send(res, 200, { ok: true });
    if (req.method === 'POST' && p === '/v2/incidents') return await handleCreate(req, res);
    if (req.method === 'POST' && (m = /^\/v2\/incidents\/([^/]+)\/receipts$/.exec(p))) return await handleReceipt(req, res, decodeURIComponent(m[1]));
    if (req.method === 'GET' && (m = /^\/v2\/incidents\/([^/]+)$/.exec(p))) {
      const st = store.get(decodeURIComponent(m[1]));
      if (!st) throw new HttpError(404, 'run_not_found');
      return send(res, 200, view(st));
    }
    throw new HttpError(404, 'not_found');
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.code }); // never echoes input
    console.error('unhandled:', e?.message);
    send(res, 500, { error: 'internal_error' });
  }
});
server.requestTimeout = 17000;
server.listen(Number(process.env.PORT) || 8080, () => console.log('incident-agent listening'));
