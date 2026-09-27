import { randomBytes } from "node:crypto";
import { sha256, equalHash } from "./receiptIntegrity.mjs";
export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
export function requireText(value, label, max = 100000) {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new HttpError(
      400,
      `${label} must be non-empty text of at most ${max} characters.`,
    );
  return value;
}
export function sessionFromRequest(db, req) {
  const token = (req.headers.cookie || "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith("aeria_session="))
    ?.slice(14);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const s = db
    .prepare(
      `SELECT s.*,m.name,m.institution_id,m.active,m.capabilities,i.connected FROM sessions s JOIN members m ON m.id=s.member_id JOIN institutions i ON i.id=m.institution_id WHERE s.token_hash=?`,
    )
    .get(sha256(token));
  if (!s || s.expires_at <= Date.now() || !s.active || !s.connected)
    return null;
  return { ...s, capabilities: JSON.parse(s.capabilities) };
}
export function checkCsrf(req, s) {
  const token = req.headers["x-csrf-token"];
  if (typeof token !== "string" || !equalHash(s.csrf_hash, sha256(token)))
    throw new HttpError(403, "Session anti-forgery token required.");
}
export function authorizeOperator(
  db,
  req,
  caseId,
  capability,
  mutation = false,
) {
  const s = sessionFromRequest(db, req);
  if (!s)
    throw new HttpError(401, "An active institutional session is required.");
  const assigned = db
    .prepare(
      "SELECT c.id FROM cases c JOIN assignments a ON a.case_id=c.id WHERE c.id=? AND c.institution_id=? AND a.member_id=?",
    )
    .get(caseId, s.institution_id, s.member_id);
  if (!assigned || !s.capabilities.includes(capability))
    throw new HttpError(
      403,
      "Institution, membership, assignment, or capability does not authorize this action.",
    );
  if (mutation) checkCsrf(req, s);
  return { kind: "HUMAN_OPERATOR", id: s.member_id };
}
export function authorizeCivilian(db, caseId, key) {
  const row = db.prepare("SELECT * FROM cases WHERE id=?").get(caseId);
  if (!row || typeof key !== "string" || !equalHash(row.key_hash, sha256(key)))
    throw new HttpError(403, "Case ID or private access key is invalid.");
  return { kind: "HUMAN_CASE_HOLDER", id: caseId };
}
export function establishDemoSession(db, memberId, secureCookies = false) {
  const token = randomBytes(32).toString("base64url"),
    csrf = randomBytes(32).toString("base64url"),
    expiresAt = Date.now() + 604800000;
  db.prepare("INSERT INTO sessions VALUES (?,?,?,?)").run(
    sha256(token),
    memberId,
    sha256(csrf),
    expiresAt,
  );
  return {
    csrf,
    expiresAt,
    cookie: `aeria_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${secureCookies ? "; Secure" : ""}`,
  };
}
