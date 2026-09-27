import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
export function canonical(v) {
  if (v === null || ["boolean", "string"].includes(typeof v))
    return JSON.stringify(v);
  if (typeof v === "number" && Number.isFinite(v)) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && Object.getPrototypeOf(v) === Object.prototype)
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
      .join(",")}}`;
  throw new TypeError("Expected finite JSON values.");
}
export const sha256 = (v) =>
  createHash("sha256").update(v, "utf8").digest("hex");
export const digest = (v) => sha256(canonical(v));
export const id = (prefix) =>
  `${prefix}_${randomBytes(18).toString("base64url")}`;
export const timestamp = () => new Date().toISOString();
export function equalHash(a, b) {
  return (
    typeof a === "string" &&
    typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) &&
    /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"))
  );
}
export const SCOPE =
  "Valid only for the supplied policy document and version. Not documented does not mean not available.";
export const AUTHORITY =
  "Extraction and classification only. No legal compliance determination, acknowledgement of a request, or initiation of escalation. Those require separately authorized human actions.";
export const METHOD = {
  name: "literal-passage-extraction",
  version: "1",
  kind: "deterministic",
  model: null,
};
export const LIMITS =
  "Verification establishes consistency of the supplied record, not truth, legal compliance, delivery, identity assurance, or completeness of history. No external anchor or trusted timestamp is configured; a database administrator can rewrite an entire record and recompute its hashes.";
export const ESTABLISHES =
  "The supplied source, recorded findings, stated method, and locally recorded actions are bound by these hashes.";
export function receiptBody(a, p) {
  return {
    schema: "aeria.policy-receipt.v1",
    canonicalization: "aeria-canonical-json-v1",
    analysisId: a.id,
    caseId: a.caseId,
    policyId: p.id,
    policyHash: sha256(p.text),
    policyVersion: p.version,
    findingManifest: a.findings,
    analysisMethod: a.method,
    scope: a.scope,
    authorityBoundary: a.authorityBoundary,
    timestamp: a.timestamp,
  };
}
export function verifyPacket(packet) {
  const issues = [];
  try {
    const { analysis: a, policy: p, receipt: r, events } = packet;
    if (packet.limitations !== LIMITS || packet.establishes !== ESTABLISHES)
      issues.push("packet_boundary");
    if (
      packet.schema !== "aeria.evidence-packet.v1" ||
      p.caseId !== a.caseId ||
      a.policyId !== p.id
    )
      issues.push("policy_binding");
    if (p.hash !== sha256(p.text)) issues.push("source_hash");
    if (
      a.scope !== SCOPE ||
      a.authorityBoundary !== AUTHORITY ||
      canonical(a.method) !== canonical(METHOD)
    )
      issues.push("unsupported_analysis_boundary_or_method");
    if (
      packet.scope !== a.scope ||
      packet.authorityBoundary !== a.authorityBoundary ||
      canonical(packet.sourcePassages) !==
        canonical(a.findings.flatMap((f) => f.passages))
    )
      issues.push("packet_projection");
    const expected = receiptBody(a, p),
      hash = digest(expected);
    if (canonical(r.body) !== canonical(expected)) issues.push("receipt_body");
    if (r.hash !== hash) issues.push("receipt_hash");
    for (const f of a.findings) {
      if (!["PASSAGE_IDENTIFIED", "NOT_DOCUMENTED"].includes(f.status))
        issues.push("finding_status");
      if (
        (f.status === "NOT_DOCUMENTED" && f.passages.length) ||
        (f.status === "PASSAGE_IDENTIFIED" && !f.passages.length)
      )
        issues.push("finding_passages");
      for (const s of f.passages)
        if (
          !Number.isInteger(s.start) ||
          !Number.isInteger(s.end) ||
          s.start < 0 ||
          s.end <= s.start ||
          s.end > p.text.length ||
          s.sourceHash !== p.hash ||
          p.text.slice(s.start, s.end) !== s.text
        )
          issues.push("source_passage");
    }
    let previous = null,
      sequence = 0;
    const states = new Map();
    for (const event of events) {
      const { hash: eventHash, ...body } = event;
      if (
        event.caseId !== a.caseId ||
        event.sequence !== ++sequence ||
        event.previousHash !== previous ||
        digest(body) !== eventHash
      )
        issues.push("event_chain");
      previous = eventHash;
      if (event.type === "REQUEST_SUBMITTED")
        states.set(event.payload.requestId, "SUBMITTED");
      if (event.type === "REQUEST_ACKNOWLEDGED")
        states.set(event.payload.requestId, "ACKNOWLEDGED");
      if (event.type === "REQUEST_CONTENT_DELETED")
        states.set(event.payload.requestId, "CONTENT_DELETED");
    }
    if (packet.historyHead !== previous) issues.push("history_head");
    if (
      !events.some(
        (e) =>
          e.type === "POLICY_ANALYZED" &&
          e.payload.analysisId === a.id &&
          e.payload.receiptHash === r.hash &&
          e.payload.policyHash === p.hash,
      )
    )
      issues.push("analysis_event_binding");
    if (
      canonical(packet.requestStates) !==
      canonical([...states].map(([requestId, state]) => ({ requestId, state })))
    )
      issues.push("request_state");
    return {
      valid: !issues.length,
      issues: [...new Set(issues)],
      recomputedReceiptHash: hash,
      checkedEvents: events.length,
      limitations: LIMITS,
    };
  } catch {
    return { valid: false, issues: ["malformed_record"], limitations: LIMITS };
  }
}
