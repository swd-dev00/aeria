import http from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { openDatabase } from "./helpers/db.mjs";
import {
  HttpError,
  requireText,
  sessionFromRequest,
  checkCsrf,
  authorizeCivilian,
  authorizeOperator,
  establishDemoSession,
} from "./helpers/accessLayerAuth.mjs";
import {
  createCase,
  analyze,
  submitRequest,
  transitionRequest,
  caseBundle,
  packet,
  exportPacket,
  seedDemo,
} from "./helpers/civicGovernance.mjs";
import { verifyPacket } from "./helpers/receiptIntegrity.mjs";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const aliases = new Map([
  ["civilian-case-v2", "/api/cases"],
  ["civilian-case-v2-read", "/api/cases/read"],
  ["civilian-record-request", "/api/requests"],
  ["aeria-case-review", "/api/policies/analyze"],
  ["accesslayer-cases", "/api/accesslayer/cases"],
  ["accesslayer-case-read", "/api/accesslayer/read"],
  ["accesslayer-case-update", "/api/requests/acknowledge"],
]);
const routes = new Set(["/", "/workspace", "/login", "/governance"]);
async function readBody(req) {
  if (!(req.headers["content-type"] || "").startsWith("application/json"))
    throw new HttpError(415, "Use application/json.");
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 500000) throw new HttpError(413, "Request body too large.");
    chunks.push(chunk);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
      throw new Error();
    return parsed;
  } catch {
    throw new HttpError(400, "Expected a JSON object.");
  }
}
export function createApp({
  database = ":memory:",
  demo = false,
  secureCookies = false,
} = {}) {
  const db = openDatabase(database);
  if (demo) seedDemo(db);
  const server = http.createServer(async (req, res) => {
    const json = (status, body, headers = {}) => {
      res.writeHead(status, {
        "content-type": "application/json; charset=utf-8",
        ...headers,
      });
      res.end(JSON.stringify(body));
    };
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader(
      "content-security-policy",
      "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    try {
      const port = server.address().port;
      const origins = new Set([
        `http://127.0.0.1:${port}`,
        `http://localhost:${port}`,
      ]);
      if (!origins.has(`http://${req.headers.host}`))
        throw new HttpError(403, "Unrecognized local host.");
      if (
        req.method === "POST" &&
        (!origins.has(req.headers.origin) ||
          req.headers.origin !== `http://${req.headers.host}`)
      )
        throw new HttpError(403, "Same-origin request required.");
      let pathname = new URL(req.url, "http://localhost").pathname;
      if (pathname.startsWith("/_api/")) {
        const original = pathname.slice(6);
        pathname = aliases.get(original) || `/api/${original}`;
      }
      if (req.method === "GET" && pathname === "/api/health")
        return json(200, {
          ok: true,
          demo,
          authentication: demo
            ? "SYNTHETIC_DEMO_ONLY"
            : "IDENTITY_PROVIDER_NOT_CONFIGURED",
        });
      if (req.method === "GET" && pathname === "/api/auth/session") {
        const s = sessionFromRequest(db, req);
        return json(200, {
          user: s
            ? {
                id: s.member_id,
                name: s.name,
                institutionId: s.institution_id,
                capabilities: s.capabilities,
                expiresAt: s.expires_at,
              }
            : null,
          demo,
        });
      }
      if (pathname.startsWith("/api/auth/microsoft_login_"))
        throw new HttpError(
          503,
          "Microsoft identity integration is not configured. No OAuth callback or client-supplied identity is accepted.",
        );
      if (req.method === "GET") {
        const file = routes.has(pathname)
          ? "index.html"
          : { "/app.js": "app.js", "/styles.css": "styles.css" }[pathname];
        if (!file) throw new HttpError(404, "Route not found.");
        res.setHeader(
          "content-type",
          `${{ ".html": "text/html", ".js": "text/javascript", ".css": "text/css" }[path.extname(file)]}; charset=utf-8`,
        );
        return res.end(readFileSync(path.join(root, "public", file)));
      }
      if (req.method !== "POST")
        throw new HttpError(405, "Method not allowed.");
      const body = await readBody(req);
      if (pathname === "/api/auth/demo-login") {
        if (!demo) throw new HttpError(404, "Demo sign-in is disabled.");
        const roles = { organizer: "demo-organizer", auditor: "demo-auditor" };
        const memberId = Object.hasOwn(roles, body.role)
          ? roles[body.role]
          : null;
        if (!memberId)
          throw new HttpError(400, "Choose a synthetic demo role.");
        const old = sessionFromRequest(db, req);
        if (old)
          db.prepare("DELETE FROM sessions WHERE token_hash=?").run(
            old.token_hash,
          );
        const s = establishDemoSession(db, memberId, secureCookies);
        return json(
          200,
          { csrf: s.csrf, expiresAt: s.expiresAt, demo: true },
          { "set-cookie": s.cookie },
        );
      }
      if (pathname === "/api/auth/logout") {
        const s = sessionFromRequest(db, req);
        if (s) {
          checkCsrf(req, s);
          db.prepare("DELETE FROM sessions WHERE token_hash=?").run(
            s.token_hash,
          );
        }
        return json(
          200,
          { ok: true },
          {
            "set-cookie": `aeria_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookies ? "; Secure" : ""}`,
          },
        );
      }
      if (pathname === "/api/cases") {
        if (!demo)
          throw new HttpError(
            503,
            "Institution provisioning is required. Use --demo for synthetic local testing.",
          );
        return json(201, createCase(db, "demo-institution"));
      }
      if (pathname === "/api/accesslayer/cases") {
        const s = sessionFromRequest(db, req);
        if (!s) throw new HttpError(401, "Institutional session required.");
        checkCsrf(req, s);
        if (!s.capabilities.includes("READ"))
          throw new HttpError(403, "READ capability required.");
        return json(200, {
          cases: db
            .prepare(
              "SELECT c.id,c.created_at FROM cases c JOIN assignments a ON a.case_id=c.id WHERE c.institution_id=? AND a.member_id=? ORDER BY c.created_at DESC",
            )
            .all(s.institution_id, s.member_id),
        });
      }
      const caseRoutes = new Set([
        "/api/cases/read",
        "/api/accesslayer/read",
        "/api/policies/analyze",
        "/api/requests",
        "/api/requests/acknowledge",
        "/api/requests/delete",
        "/api/records/read",
        "/api/records/verify",
        "/api/records/export",
      ]);
      if (!caseRoutes.has(pathname))
        throw new HttpError(404, "Route not reconstructed.");
      requireText(body.caseId, "Case ID", 128);
      if (pathname.startsWith("/api/records/"))
        requireText(body.analysisId, "Analysis ID", 128);
      if (
        ["/api/requests/acknowledge", "/api/requests/delete"].includes(pathname)
      )
        requireText(body.requestId, "Request ID", 128);
      const readActor = () =>
        typeof body.accessKey === "string"
          ? authorizeCivilian(db, body.caseId, body.accessKey)
          : authorizeOperator(db, req, body.caseId, "READ");
      if (pathname === "/api/cases/read") {
        authorizeCivilian(db, body.caseId, body.accessKey);
        return json(200, caseBundle(db, body.caseId));
      }
      if (pathname === "/api/accesslayer/read") {
        authorizeOperator(db, req, body.caseId, "READ");
        return json(200, caseBundle(db, body.caseId));
      }
      if (pathname === "/api/policies/analyze") {
        const actor =
          typeof body.accessKey === "string"
            ? authorizeCivilian(db, body.caseId, body.accessKey)
            : authorizeOperator(db, req, body.caseId, "ANALYZE", true);
        return json(201, analyze(db, body.caseId, actor, body));
      }
      if (pathname === "/api/requests")
        return json(
          201,
          submitRequest(
            db,
            body.caseId,
            authorizeCivilian(db, body.caseId, body.accessKey),
            body.content,
          ),
        );
      if (pathname === "/api/requests/acknowledge")
        return json(
          200,
          transitionRequest(
            db,
            body.caseId,
            body.requestId,
            authorizeOperator(db, req, body.caseId, "ACKNOWLEDGE", true),
            "acknowledge",
          ),
        );
      if (pathname === "/api/requests/delete")
        return json(
          200,
          transitionRequest(
            db,
            body.caseId,
            body.requestId,
            authorizeCivilian(db, body.caseId, body.accessKey),
            "delete",
          ),
        );
      if (pathname === "/api/records/read") {
        readActor();
        return json(200, packet(db, body.caseId, body.analysisId));
      }
      if (pathname === "/api/records/verify") {
        readActor();
        return json(
          200,
          verifyPacket(packet(db, body.caseId, body.analysisId)),
        );
      }
      if (pathname === "/api/records/export") {
        const actor =
          typeof body.accessKey === "string"
            ? authorizeCivilian(db, body.caseId, body.accessKey)
            : authorizeOperator(db, req, body.caseId, "EXPORT", true);
        return json(200, exportPacket(db, body.caseId, body.analysisId, actor));
      }
      throw new HttpError(404, "Route not reconstructed.");
    } catch (error) {
      json(error.status || 500, {
        error: error.status
          ? error.message
          : "The operation failed. No internal details were returned.",
      });
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return { server, db };
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  const demo = process.argv.includes("--demo");
  const dataDir = path.join(root, "data");
  mkdirSync(dataDir, { recursive: true });
  const { server, db } = createApp({
    database: path.join(dataDir, demo ? "demo.db" : "aeria.db"),
    demo,
  });
  server.listen(Number(process.env.PORT || 4310), "127.0.0.1", () =>
    console.log(
      `Aeria: http://127.0.0.1:${server.address().port} (${demo ? "synthetic demo" : "identity provider not configured"})`,
    ),
  );
  const shutdown = () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
    server.closeIdleConnections();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
