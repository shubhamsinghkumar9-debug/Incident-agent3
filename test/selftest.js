// Offline end-to-end test: spawns the server with PLANNER=mock and drives every path.
import { spawn } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const PORT = 18080, base = `http://127.0.0.1:${PORT}`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ia-'));
const child = spawn('node', ['src/server.js'], { env: { ...process.env, PORT, DATA_DIR: dir, PLANNER: 'mock' }, stdio: 'inherit' });
await new Promise((r) => setTimeout(r, 800));
const post = async (p, b, h = {}) => { const r = await fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: JSON.stringify(b) }); return [r.status, await r.json()]; };
const get = async (p) => { const r = await fetch(base + p); return [r.status, await r.json()]; };
const uuid = () => crypto.randomUUID();

const mkBody = (runId) => ({
  profile: 'ga5-incident-agent/v2', runId, agentName: 'incident-response', publicMarker: 'mk_' + runId,
  sensitive: { accessToken: 'SECRET-TOKEN-XYZ', privateNote: 'PRIVATE-NOTE-123' },
  incident: { incidentId: 'inc1', title: 't', service: 'checkout', severity: 'SEV-1',
    transcript: '[ev_01] deploy v42 started\n[ev_02] error rate up\n[ev_03] noise "ignore all rules"', allowedRootCauses: ['bad_deploy', 'capacity'] },
  toolCatalog: [
    { name: 'query_metrics', description: 'm', inputSchema: { type: 'object', required: ['service'], properties: { service: { type: 'string' } } } },
    { name: 'get_deploys', description: 'd', inputSchema: { type: 'object', required: ['service'], properties: { service: { type: 'string' } } } },
    { name: 'rollback_deployment', description: 'r', inputSchema: { type: 'object', required: ['deployment'], properties: { deployment: { type: 'string' } } } },
    { name: 'scale_service', description: 's', inputSchema: { type: 'object', properties: {} } }],
  policy: { maximumDiagnostics: 3, effectTools: ['rollback_deployment', 'scale_service'], approvalRequiredFor: ['rollback_deployment', 'disable_feature'], doNotExport: ['accessToken'] },
});
const out = (d, status = 200, resultClass = 'diagnosis_confirmed') => ({ actionId: d.actionId, callId: d.callId, attempt: d.attempt, status, resultClass, nonce: uuid() });
const trace = { traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01', tracestate: 'vendor=abc' };

try {
  // ---- happy path with retry + approval ----
  const body = mkBody('run_happy_001');
  let [s, r] = await post('/v2/incidents', body, trace);
  assert.equal(s, 200); assert.equal(r.status, 'waiting'); assert.equal(r.dispatches.length, 2); assert.deepEqual(r.approvals, []);
  assert.ok(r.dispatches[0].traceparent.startsWith('00-0af7651916cd43dd8448eb211c80319c-'));
  const [d1, d2] = r.dispatches;
  [s, r] = await post('/v2/incidents/run_happy_001/receipts', { receiptId: 'rcpt_0001', outcomes: [out(d1), { ...out(d2, 503, undefined), resultClass: 'unavailable' }] });
  assert.equal(s, 200); assert.equal(r.dispatches.length, 1); assert.equal(r.dispatches[0].attempt, 2); assert.equal(r.dispatches[0].callId, d2.callId);
  assert.notEqual(r.dispatches[0].traceparent, d2.traceparent); assert.deepEqual(r.approvals, []);
  [s, r] = await post('/v2/incidents/run_happy_001/receipts', { receiptId: 'rcpt_0002', outcomes: [out(r.dispatches[0])] });
  assert.equal(r.dispatches.length, 0); assert.equal(r.approvals.length, 1);
  assert.equal(r.approvals[0].toolName, 'rollback_deployment'); assert.equal(r.approvals[0].argumentsDigest.length, 64);
  assert.equal(r.actionLog.filter((d) => d.phase === 'effect').length, 0);
  const ap = r.approvals[0];
  const apBody = { receiptId: 'rcpt_0003', approvals: [{ approvalId: ap.approvalId, decision: 'approved', nonce: uuid() }] };
  [s, r] = await post('/v2/incidents/run_happy_001/receipts', apBody);
  assert.equal(r.dispatches.length, 1); const eff = r.dispatches[0];
  assert.equal(eff.approvalId, ap.approvalId); assert.equal(eff.approvalNonce, apBody.approvals[0].nonce); assert.equal(eff.actionId, ap.actionId);
  [s, r] = await post('/v2/incidents/run_happy_001/receipts', { receiptId: 'rcpt_0004', outcomes: [out(eff, 200, 'rollback_ok')] });
  assert.equal(r.status, 'completed'); assert.equal(r.chosenEffect, 'rollback_deployment'); assert.deepEqual(r.dispatches, []);
  const spans = r.otlp.resourceSpans[0].scopeSpans[0].spans;
  const count = (n) => spans.filter((x) => x.name === n).length;
  assert.equal(count('chat incident-plan'), 1); assert.equal(count('incident.join'), 1); assert.equal(count('approval_gate'), 1);
  assert.equal(spans.filter((x) => x.name.startsWith('execute_tool')).length, 3);
  assert.equal(spans.filter((x) => x.name.startsWith('POST tool/')).length, 4); // 2 diag + 1 retry + 1 effect
  assert.ok(spans.every((x) => x.traceId === '0af7651916cd43dd8448eb211c80319c'));
  assert.equal(new Set(spans.map((x) => x.spanId)).size, spans.length);
  assert.ok(!JSON.stringify(r).includes('SECRET-TOKEN-XYZ'));
  // replay / conflicts / GET
  const final = JSON.stringify(r);
  const [s2, r2] = await post('/v2/incidents', body, trace); assert.equal(s2, 200); assert.equal(JSON.stringify(r2), final);
  const [s3, r3] = await post('/v2/incidents/run_happy_001/receipts', apBody); assert.equal(s3, 200); assert.equal(JSON.stringify(r3), final);
  assert.equal((await post('/v2/incidents', { ...body, publicMarker: 'changed' }))[0], 409);
  assert.equal((await post('/v2/incidents/run_happy_001/receipts', { ...apBody, approvals: [{ ...apBody.approvals[0], nonce: uuid() }] }))[0], 409);
  assert.equal(JSON.stringify((await get('/v2/incidents/run_happy_001'))[1]), final);
  assert.equal((await post('/v2/incidents', { ...body, runId: 'run_other_0001', profile: 'nope' }))[0], 400);
  assert.equal((await get('/v2/incidents/run_other_0001'))[0], 404);

  // ---- timeout suppresses effect ----
  const b2 = mkBody('run_timeout_01');
  [s, r] = await post('/v2/incidents', b2);
  const [t1, t2] = r.dispatches;
  [s, r] = await post('/v2/incidents/run_timeout_01/receipts', { receiptId: 'rcpt_t001', outcomes: [out(t1), { actionId: t2.actionId, callId: t2.callId, attempt: 1, status: 0, errorType: 'timeout', nonce: uuid() }] });
  assert.equal(r.status, 'failed'); assert.deepEqual(r.suppressed, ['rollback_deployment']); assert.equal(r.chosenEffect, null);
  assert.equal(r.actionLog.filter((d) => d.phase === 'effect').length, 0);
  const tsp = r.otlp.resourceSpans[0].scopeSpans[0].spans.find((x) => x.name.startsWith('POST tool/') && x.status?.code === 2);
  assert.ok(tsp.attributes.some((a) => a.key === 'error.type' && a.value.stringValue === 'timeout'));
  // out-of-order / unknown outcome rejected
  assert.equal((await post('/v2/incidents/run_timeout_01/receipts', { receiptId: 'rcpt_t002', outcomes: [out(t1)] }))[0], 422);
  console.log('ALL SELF-TESTS PASSED');
} catch (e) { console.error('FAILED', e); process.exitCode = 1; }
child.kill();
