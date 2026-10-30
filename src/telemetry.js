// Builds the OTLP/JSON trace purely from stored state (dispatches + receipts). No model, no randomness.
import { pendingDispatches, pendingApprovals } from './machine.js';

const B = (s) => BigInt(s);
const add = (s, n) => (B(s) + BigInt(n)).toString();
const max = (a, b) => (B(a) > B(b) ? a : b);

const attr = (k, v) => ({
  key: k,
  value: typeof v === 'number' ? { intValue: v } : typeof v === 'boolean' ? { boolValue: v } : { stringValue: String(v) },
});

export function buildOtlp(st) {
  const base = [attr('ga5.run.id', st.runId), attr('ga5.public.marker', st.publicMarker)];
  const span = (name, kind, spanId, parent, start, end, attrs, extra = {}) => {
    const s = { traceId: st.traceId, spanId, name, kind, startTimeUnixNano: start, endTimeUnixNano: end, attributes: [...base, ...attrs] };
    if (parent) s.parentSpanId = parent;
    if (st.tracestate) s.traceState = st.tracestate;
    return Object.assign(s, extra);
  };
  const children = [];
  let maxEnd = st.modelEnd;

  // one model call
  children.push(span('chat incident-plan', 3, st.ids.model, st.ids.agent, st.modelStart, st.modelEnd, [
    attr('gen_ai.operation.name', 'chat'), attr('gen_ai.request.model', st.model), attr('gen_ai.system', 'openai-compatible'),
  ]));

  const execEnd = {};
  for (const a of st.actions) {
    const atts = st.attempts[a.callId] || [];
    let end = a.startNs;
    const clients = [];
    for (const t of atts) {
      if (!t.outcome) continue;
      const o = t.outcome;
      const cs = add(t.dispatchNs, 1000), ce = t.receiptNs;
      const attrs = [
        attr('ga5.action.id', a.actionId), attr('gen_ai.tool.name', a.toolName),
        attr('gen_ai.tool.call.id', a.callId), attr('ga5.attempt', t.attempt),
        attr('ga5.receipt.id', o.receiptId), attr('ga5.receipt.nonce', o.nonce),
        attr('http.request.method', 'POST'), attr('http.request.resend_count', t.attempt - 1),
      ];
      if (o.status > 0) attrs.push(attr('http.response.status_code', o.status));
      let status;
      if (o.status >= 200 && o.status < 300) status = { code: 1 };
      else { attrs.push(attr('error.type', o.status === 0 ? 'timeout' : String(o.status))); status = { code: 2 }; }
      clients.push(span(`POST tool/${a.toolName}`, 3, t.spanId, a.execSpanId, cs, ce, attrs, { status }));
      end = max(end, add(ce, 0));
    }
    const pend = atts.some((t) => !t.outcome);
    const eEnd = add(pend ? max(end, st.lastNs) : end, 1000);
    execEnd[a.callId] = eEnd;
    children.push(span(`execute_tool ${a.toolName}`, 1, a.execSpanId, st.ids.agent, a.startNs, eEnd, [
      attr('ga5.action.id', a.actionId), attr('gen_ai.tool.name', a.toolName), attr('gen_ai.tool.call.id', a.callId),
      attr('gen_ai.operation.name', 'execute_tool'), attr('ga5.phase', a.phase),
      attr('ga5.attempt.count', atts.length),
      ...(a.approvalId ? [attr('ga5.approval.id', a.approvalId)] : []),
      ...(a.approvalNonce ? [attr('ga5.approval.nonce', a.approvalNonce)] : []),
    ]));
    children.push(...clients);
    maxEnd = max(maxEnd, eEnd);
  }

  const diagActs = st.actions.filter((a) => a.phase === 'diagnostic');
  if (diagActs.length > 0) {
    let jStart = st.modelEnd;
    for (const a of diagActs) jStart = max(jStart, execEnd[a.callId]);
    jStart = add(jStart, 1000);
    const jEnd = add(jStart, 1000);
    children.push(span('incident.join', 1, st.ids.join, st.ids.agent, jStart, jEnd, [attr('ga5.join.count', diagActs.length)], {
      links: diagActs.map((a) => ({ traceId: st.traceId, spanId: a.execSpanId, attributes: [] })),
    }));
    maxEnd = max(maxEnd, jEnd);
  }

  if (st.approval) {
    const ap = st.approval;
    const gEnd = add(ap.receivedNs || st.lastNs, 0);
    const effectDef = st.defs[st.effectCall];
    const attrs = [
      attr('ga5.approval.id', ap.approvalId),
      attr('ga5.action.id', ap.actionId),
      attr('gen_ai.tool.name', ap.toolName),
      attr('gen_ai.tool.call.id', effectDef.callId),
      attr('ga5.arguments.digest', ap.argumentsDigest),
    ];
    if (ap.decision) {
      attrs.push(attr('ga5.approval.decision', ap.decision), attr('ga5.approval.nonce', ap.nonce),
        attr('ga5.approval.receipt.nonce', ap.nonce), attr('ga5.receipt.id', ap.receiptId), attr('ga5.receipt.nonce', ap.nonce));
    }
    children.push(span('approval_gate', 1, st.ids.gate, st.ids.agent, ap.requestedNs, gEnd, attrs));
    maxEnd = max(maxEnd, gEnd);
  }

  maxEnd = max(maxEnd, st.lastNs);
  const agentEnd = add(maxEnd, 1000), serverEnd = add(agentEnd, 1000);
  const agent = span(`invoke_agent ${st.agentName}`, 1, st.ids.agent, st.ids.server, st.t0, agentEnd, [
    attr('gen_ai.operation.name', 'invoke_agent'), attr('gen_ai.agent.name', st.agentName),
  ]);
  const server = span('POST /v2/incidents', 2, st.ids.server, st.parentSpanId, st.t0, serverEnd, [
    attr('http.request.method', 'POST'), attr('http.route', '/v2/incidents'), attr('http.response.status_code', 200),
  ]);
  return { resourceSpans: [{ resource: { attributes: [attr('service.name', 'incident-agent')] }, scopeSpans: [{ scope: { name: 'ga5.incident-agent' }, spans: [server, agent, ...children] }] }] };
}

export function view(st) {
  return {
    runId: st.runId,
    status: st.status,
    diagnosis: st.diagnosis,
    chosenEffect: st.chosenEffect,
    suppressed: st.suppressed,
    actionLog: st.actionLog,
    receiptLog: st.receiptLog,
    dispatches: pendingDispatches(st),
    approvals: pendingApprovals(st),
    otlp: buildOtlp(st),
  };
}
