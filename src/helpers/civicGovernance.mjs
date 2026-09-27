import { transaction } from "./db.mjs";
import { HttpError, requireText } from "./accessLayerAuth.mjs";
import {
  id,
  timestamp,
  sha256,
  digest,
  receiptBody,
  verifyPacket,
  SCOPE,
  AUTHORITY,
  METHOD,
  LIMITS,
  ESTABLISHES,
} from "./receiptIntegrity.mjs";

const categories = [
  [
    "decision",
    "Decision or stated reason",
    /\b(decision|denied|approved|reason|because|determination|eligible|ineligible|available|unavailable|accepted|rejected)\b/i,
  ],
  [
    "process",
    "Process, review, or contact path",
    /\b(review|appeal|request|contact|submit|process|reconsider|response|respond)\w*\b/i,
  ],
  [
    "timing",
    "Timing and receipt",
    /\b(receiv\w*|submit\w*|timestamp|deadline|before|after|date|time)\b/i,
  ],
  [
    "authority",
    "Rule or authority cited",
    /\b(policy|rule|regulation|procedure|criteria|requirement|standard)\b/i,
  ],
];
export function extractFindings(policy) {
  return categories.map(([key, label, pattern]) => {
    const passages = [];
    for (const match of policy.text.matchAll(/[^.!?\r\n]+(?:[.!?]+|$)/gm)) {
      const text = match[0].trim();
      if (!pattern.test(text)) continue;
      const start = match.index + match[0].indexOf(text);
      passages.push({
        start,
        end: start + text.length,
        text,
        sourceHash: policy.hash,
      });
    }
    return {
      id: key,
      label,
      status: passages.length ? "PASSAGE_IDENTIFIED" : "NOT_DOCUMENTED",
      passages,
      boundary: passages.length
        ? "A related passage was identified. Wording, conditions, and negations remain controlling; this does not establish correctness, intent, or remedy."
        : "No matching passage was identified by this literal method in the supplied source. Relevant evidence may exist elsewhere or use different wording.",
    };
  });
}
export function appendEvent(db, caseId, type, actor, payload) {
  const previous = db
    .prepare(
      "SELECT sequence,hash FROM events WHERE case_id=? ORDER BY sequence DESC LIMIT 1",
    )
    .get(caseId);
  const body = {
    id: id("evt"),
    caseId,
    sequence: (previous?.sequence || 0) + 1,
    type,
    actor,
    payload,
    timestamp: timestamp(),
    previousHash: previous?.hash || null,
  };
  const hash = digest(body);
  db.prepare("INSERT INTO events VALUES (?,?,?,?)").run(
    caseId,
    body.sequence,
    JSON.stringify(body),
    hash,
  );
  return { ...body, hash };
}
export function createCase(db, institutionId) {
  if (!db.prepare("SELECT id FROM institutions WHERE id=?").get(institutionId))
    throw new HttpError(400, "Unknown institution.");
  return transaction(db, () => {
    const caseId = id("case"),
      accessKey = id("key");
    db.prepare("INSERT INTO cases VALUES (?,?,?,?)").run(
      caseId,
      institutionId,
      sha256(accessKey),
      timestamp(),
    );
    // Automatic assignments are restricted to the explicitly synthetic fixture.
    if (institutionId === "demo-institution")
      for (const member of db
        .prepare("SELECT id FROM members WHERE institution_id=?")
        .all(institutionId))
        db.prepare("INSERT INTO assignments VALUES (?,?)").run(
          caseId,
          member.id,
        );
    appendEvent(
      db,
      caseId,
      "CASE_CREATED",
      { kind: "HUMAN_CASE_HOLDER", id: caseId },
      {},
    );
    return { caseId, accessKey };
  });
}
export function analyze(db, caseId, actor, input) {
  const text = requireText(input.policyText, "Policy text");
  const version = requireText(input.policyVersion, "Policy version", 120);
  return transaction(db, () => {
    const policy = { id: id("pol"), caseId, version, text, hash: sha256(text) };
    const analysis = {
      id: id("ana"),
      caseId,
      policyId: policy.id,
      findings: extractFindings(policy),
      method: METHOD,
      scope: SCOPE,
      authorityBoundary: AUTHORITY,
      timestamp: timestamp(),
    };
    const body = receiptBody(analysis, policy),
      hash = digest(body);
    db.prepare("INSERT INTO policies VALUES (?,?,?)").run(
      policy.id,
      caseId,
      JSON.stringify(policy),
    );
    db.prepare("INSERT INTO analyses VALUES (?,?,?,?)").run(
      analysis.id,
      caseId,
      policy.id,
      JSON.stringify(analysis),
    );
    db.prepare("INSERT INTO receipts VALUES (?,?,?)").run(
      analysis.id,
      JSON.stringify(body),
      hash,
    );
    appendEvent(db, caseId, "POLICY_ANALYZED", actor, {
      analysisId: analysis.id,
      policyHash: policy.hash,
      receiptHash: hash,
    });
    return { analysisId: analysis.id, receiptHash: hash };
  });
}
export function submitRequest(db, caseId, actor, content) {
  requireText(content, "Requested record", 5000);
  if (actor.kind !== "HUMAN_CASE_HOLDER")
    throw new HttpError(403, "A case holder must submit a request.");
  return transaction(db, () => {
    const requestId = id("req");
    db.prepare("INSERT INTO requests VALUES (?,?,?)").run(
      requestId,
      caseId,
      "SUBMITTED",
    );
    db.prepare("INSERT INTO request_content VALUES (?,?)").run(
      requestId,
      content,
    );
    // Never retain sensitive content or a guessable hash of that content in history.
    appendEvent(db, caseId, "REQUEST_SUBMITTED", actor, { requestId });
    return {
      requestId,
      state: "SUBMITTED",
      boundary:
        "Recorded locally. This is not proof of external delivery or institutional acknowledgement.",
    };
  });
}
export function transitionRequest(db, caseId, requestId, actor, action) {
  return transaction(db, () => {
    const request = db
      .prepare("SELECT * FROM requests WHERE id=? AND case_id=?")
      .get(requestId, caseId);
    if (!request) throw new HttpError(404, "Request not found.");
    if (action === "acknowledge") {
      if (actor.kind !== "HUMAN_OPERATOR")
        throw new HttpError(
          403,
          "Only an authorized human operator can acknowledge.",
        );
      if (request.state !== "SUBMITTED")
        throw new HttpError(
          409,
          "Only a submitted request can be acknowledged.",
        );
      db.prepare("UPDATE requests SET state=? WHERE id=?").run(
        "ACKNOWLEDGED",
        requestId,
      );
      appendEvent(db, caseId, "REQUEST_ACKNOWLEDGED", actor, { requestId });
      return { requestId, state: "ACKNOWLEDGED" };
    }
    if (action !== "delete") throw new HttpError(400, "Unknown transition.");
    if (actor.kind !== "HUMAN_CASE_HOLDER")
      throw new HttpError(
        403,
        "Only the case holder can delete their request content.",
      );
    if (request.state !== "CONTENT_DELETED") {
      db.prepare("DELETE FROM request_content WHERE request_id=?").run(
        requestId,
      );
      db.prepare("UPDATE requests SET state=? WHERE id=?").run(
        "CONTENT_DELETED",
        requestId,
      );
      appendEvent(db, caseId, "REQUEST_CONTENT_DELETED", actor, { requestId });
    }
    return { requestId, state: "CONTENT_DELETED" };
  });
}
export function caseBundle(db, caseId) {
  return {
    caseId,
    analyses: db
      .prepare("SELECT body FROM analyses WHERE case_id=? ORDER BY rowid")
      .all(caseId)
      .map((r) => JSON.parse(r.body)),
    requests: db
      .prepare(
        "SELECT r.id,r.state,c.content FROM requests r LEFT JOIN request_content c ON c.request_id=r.id WHERE r.case_id=? ORDER BY r.rowid",
      )
      .all(caseId),
    events: db
      .prepare("SELECT body,hash FROM events WHERE case_id=? ORDER BY sequence")
      .all(caseId)
      .map((r) => ({ ...JSON.parse(r.body), hash: r.hash })),
  };
}
export function packet(db, caseId, analysisId) {
  const row = db
    .prepare("SELECT * FROM analyses WHERE id=? AND case_id=?")
    .get(analysisId, caseId);
  if (!row) throw new HttpError(404, "Analysis not found.");
  const analysis = JSON.parse(row.body);
  const policy = JSON.parse(
    db
      .prepare("SELECT body FROM policies WHERE id=? AND case_id=?")
      .get(row.policy_id, caseId).body,
  );
  const receipt = db
    .prepare("SELECT body,hash FROM receipts WHERE analysis_id=?")
    .get(analysisId);
  const bundle = caseBundle(db, caseId);
  return {
    schema: "aeria.evidence-packet.v1",
    policy,
    analysis,
    receipt: { body: JSON.parse(receipt.body), hash: receipt.hash },
    sourcePassages: analysis.findings.flatMap((f) => f.passages),
    scope: analysis.scope,
    authorityBoundary: analysis.authorityBoundary,
    requestStates: bundle.requests.map((r) => ({
      requestId: r.id,
      state: r.state,
    })),
    events: bundle.events,
    historyHead: bundle.events.at(-1)?.hash || null,
    establishes: ESTABLISHES,
    limitations: LIMITS,
  };
}
export function exportPacket(db, caseId, analysisId, actor) {
  return transaction(db, () => {
    const before = packet(db, caseId, analysisId);
    if (!verifyPacket(before).valid)
      throw new HttpError(
        409,
        "Integrity verification failed; export blocked.",
      );
    appendEvent(db, caseId, "EVIDENCE_PACKET_EXPORTED", actor, {
      analysisId,
      receiptHash: before.receipt.hash,
    });
    return packet(db, caseId, analysisId);
  });
}
export function seedDemo(db) {
  db.prepare("INSERT OR IGNORE INTO institutions VALUES (?,?,?)").run(
    "demo-institution",
    "Demo Institution",
    1,
  );
  db.prepare("INSERT OR IGNORE INTO members VALUES (?,?,?,?,?)").run(
    "demo-organizer",
    "demo-institution",
    "Demo caseworker",
    1,
    JSON.stringify(["READ", "ANALYZE", "ACKNOWLEDGE", "EXPORT"]),
  );
  db.prepare("INSERT OR IGNORE INTO members VALUES (?,?,?,?,?)").run(
    "demo-auditor",
    "demo-institution",
    "Demo auditor",
    1,
    JSON.stringify(["READ", "EXPORT"]),
  );
}
