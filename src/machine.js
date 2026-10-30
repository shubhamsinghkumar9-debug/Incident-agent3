// Receipt-driven state machine. Pure state transitions - never calls a model.
import { canon, sha256, newId, hex, nowNs, HttpError } from './util.js';

const isOk = (o) => o && o.status >= 200 && o.status < 300;
const last = (st, callId) => { const a = st.attempts[callId]; return a && a[a.length - 1]; };

export function createRun({ body, reqHash, incoming, planned, model, t0, modelStart, modelEnd, secrets }) {
  const traceId = incoming?.traceId || hex(16);
  const scrub = (obj) => {
    let s = JSON.stringify(obj);
    for (const sec of secrets) s = s.split(JSON.stringify(sec).slice(1, -1)).join('[REDACTED]');
    return JSON.parse(s);
  };
  const defs = {};
  const mk = (phase, d) => ({
    actionId: newId('act'), callId: newId('call'), phase, toolName: d.toolName,
    arguments: scrub(d.arguments), evidence: d.evidence,
  });
  const diagnostics = planned.diagnostics.map((d) => mk('diagnostic', d));
  const effect = mk('effect', planned.effect);
  for (const a of [...diagnostics, effect]) defs[a.callId] = a;
  const st = {
    v: 1, runId: body.runId, reqHash, agentName: body.agentName, publicMarker: body.publicMarker,
    traceId, parentSpanId: incoming?.spanId || null, tracestate: incoming?.tracestate || null,
    ids: { server: hex(8), agent: hex(8), model: hex(8), join: hex(8), gate: hex(8) },
    model, t0, modelStart, modelEnd, lastNs: modelEnd,
    approvalRequiredFor: body.policy.approvalRequiredFor,
    diagnosis: planned.diagnosis, diagnosticCalls: diagnostics.map((d) => d.callId), effectCall: effect.callId,
    defs, status: 'waiting', final: false, chosenEffect: null, suppressed: [],
    actionLog: [], receiptLog: [], attempts: {}, actions: [], approval: null, receipts: {},
  };
  for (const d of diagnostics) issue(st, d, 1);
  return st;
}

function issue(st, a, attempt, extra = {}) {
  const spanId = hex(8);
  const d = {
    actionId: a.actionId, callId: a.callId, phase: a.phase, toolName: a.toolName,
    arguments: a.arguments, evidence: a.evidence, attempt,
    traceparent: `00-${st.traceId}-${spanId}-01`, ...extra,
  };
  if (st.tracestate) d.tracestate = st.tracestate;
  const ns = nowNs();
  st.actionLog.push(d);
  (st.attempts[a.callId] ||= []).push({ attempt, actionId: a.actionId, spanId, dispatchNs: ns, idx: st.actionLog.length - 1, outcome: null });
  if (attempt === 1) st.actions.push({ actionId: a.actionId, callId: a.callId, phase: a.phase, toolName: a.toolName, execSpanId: hex(8), startNs: ns });
  st.lastNs = ns;
  return d;
}

const pendingCalls = (st) => Object.keys(st.attempts).filter((c) => !last(st, c).outcome);

export function pendingDispatches(st) {
  return pendingCalls(st).map((c) => st.actionLog[last(st, c).idx]);
}
export function pendingApprovals(st) {
  const a = st.approval;
  return a && !a.decision ? [{ approvalId: a.approvalId, actionId: a.actionId, toolName: a.toolName, argumentsDigest: a.argumentsDigest }] : [];
}

function finish(st, ok) { st.final = true; st.status = ok ? 'completed' : 'failed'; }
function suppress(st) {
  st.suppressed = [st.defs[st.effectCall].toolName];
  st.chosenEffect = null;
  finish(st, false);
}

function advance(st) {
  if (st.final || pendingCalls(st).length) return;
  if (st.diagnosticCalls.some((c) => !isOk(last(st, c).outcome))) return suppress(st);
  const eff = st.defs[st.effectCall];
  const ea = st.attempts[eff.callId];
  if (ea) { st.chosenEffect = eff.toolName; return finish(st, isOk(last(st, eff.callId).outcome)); }
  if (st.approvalRequiredFor.includes(eff.toolName)) {
    if (!st.approval) {
      st.approval = {
        approvalId: newId('appr'), actionId: eff.actionId, toolName: eff.toolName,
        argumentsDigest: sha256(canon(eff.arguments)), requestedNs: nowNs(), decision: null,
      };
      st.lastNs = st.approval.requestedNs;
      st.chosenEffect = eff.toolName;
      return;
    }
    if (!st.approval.decision) return;
    if (st.approval.decision !== 'approved') return suppress(st);
    issue(st, eff, 1, { approvalId: st.approval.approvalId, approvalNonce: st.approval.nonce });
    return;
  }
  st.chosenEffect = eff.toolName;
  issue(st, eff, 1);
}

export function applyReceipt(st, body) {
  const bad = () => { throw new HttpError(422, 'invalid_receipt'); };
  if (st.final) throw new HttpError(422, 'run_already_final');
  if (body.outcomes !== undefined && !Array.isArray(body.outcomes)) bad();
  if (body.approvals !== undefined && !Array.isArray(body.approvals)) bad();
  const outcomes = body.outcomes || [], approvals = body.approvals || [];
  if (!outcomes.length && !approvals.length) bad();
  if (approvals.length > 1) bad();
  const seen = new Set(), work = [];
  for (const o of outcomes) {
    if (!o || typeof o !== 'object') bad();
    const { actionId, callId, attempt, status, nonce } = o;
    if (typeof actionId !== 'string' || typeof callId !== 'string' || !Number.isInteger(attempt) ||
        !Number.isInteger(status) || typeof nonce !== 'string' || !nonce) bad();
    const cur = st.attempts[callId] && last(st, callId);
    if (!cur || cur.outcome || cur.actionId !== actionId || cur.attempt !== attempt || seen.has(callId)) bad();
    if (status === 0 ? o.errorType !== 'timeout' : status < 100 || status > 599) bad();
    seen.add(callId);
    work.push({ o, cur });
  }
  for (const a of approvals) {
    if (!a || typeof a !== 'object' || !st.approval || st.approval.decision || a.approvalId !== st.approval.approvalId ||
        !['approved', 'denied', 'rejected'].includes(a.decision) || typeof a.nonce !== 'string' || !a.nonce) bad();
  }
  // ---- apply (validated, so no partial failure) ----
  const rid = body.receiptId;
  for (const { o, cur } of work) {
    cur.receiptNs = nowNs();
    cur.outcome = { receiptId: rid, status: o.status, resultClass: o.resultClass, errorType: o.errorType, nonce: o.nonce };
    const entry = { receiptId: rid, actionId: o.actionId, callId: o.callId, attempt: o.attempt, status: o.status };
    if (typeof o.resultClass === 'string') entry.resultClass = o.resultClass;
    if (o.status === 0) entry.errorType = o.errorType;
    entry.nonce = o.nonce;
    st.receiptLog.push(entry);
    st.lastNs = cur.receiptNs;
  }
  for (const a of approvals) {
    const ap = st.approval;
    ap.decision = a.decision; ap.nonce = a.nonce; ap.receiptId = rid; ap.receivedNs = nowNs();
    st.lastNs = ap.receivedNs;
    st.receiptLog.push({ receiptId: rid, approvalId: a.approvalId, decision: a.decision, nonce: a.nonce });
  }
  // exactly one retry for a 503 on the first attempt
  for (const { o } of work) {
    if (o.status === 503 && o.attempt === 1) {
      const prev = st.actionLog[st.attempts[o.callId][0].idx];
      const extra = {};
      if (prev.approvalId) { extra.approvalId = prev.approvalId; extra.approvalNonce = prev.approvalNonce; }
      issue(st, st.defs[o.callId], 2, extra);
    }
  }
  advance(st);
}
