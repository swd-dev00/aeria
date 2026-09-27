import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import path from "node:path";
import { createApp } from "../src/server.mjs";
import {
  canonical,
  digest,
  sha256,
  verifyPacket,
} from "../src/helpers/receiptIntegrity.mjs";
import {
  createCase,
  analyze,
  seedDemo,
  submitRequest,
  transitionRequest,
  packet,
} from "../src/helpers/civicGovernance.mjs";
import { openDatabase } from "../src/helpers/db.mjs";

async function boot(t, options = {}) {
  const app = createApp({ demo: true, ...options });
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  t.after(async () => {
    app.server.closeAllConnections();
    await new Promise((resolve) => app.server.close(resolve));
    app.db.close();
  });
  const call = async (url, body = {}, headers = {}) => {
    const res = await fetch(origin + url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: origin,
        ...headers,
      },
      body: JSON.stringify(body),
    });
    return { status: res.status, headers: res.headers, body: await res.json() };
  };
  const login = async (role) => {
    const result = await call("/api/auth/demo-login", { role });
    assert.equal(result.status, 200);
    return {
      Cookie: result.headers.get("set-cookie").split(";")[0],
      "X-CSRF-Token": result.body.csrf,
    };
  };
  const newCase = async () => {
    const result = await call("/_api/civilian-case-v2");
    assert.equal(result.status, 201);
    return result.body;
  };
  const newAnalysis = async (c) => {
    const result = await call("/_api/aeria-case-review", {
      ...c,
      policyText:
        "  Your application was denied because the required identifier was missing.\r\nA review may be requested.\nContact the records office.  ",
      policyVersion: "provided-v1",
    });
    assert.equal(result.status, 201);
    return { ...c, ...result.body };
  };
  return { ...app, origin, call, login, newCase, newAnalysis };
}

test("canonical receipts are deterministic and reject non-JSON values", () => {
  assert.equal(
    digest({ z: ["é", 2], a: true }),
    digest({ a: true, z: ["é", 2] }),
  );
  assert.notEqual(digest([1, 2]), digest([2, 1]));
  assert.throws(() => canonical({ absent: undefined }));
  assert.throws(() => canonical(Infinity));
});

test("original page and auth routes exist; Microsoft and demo auth fail closed by default", async (t) => {
  const a = await boot(t, { demo: false });
  for (const route of ["/", "/workspace", "/login", "/governance"]) {
    const res = await fetch(a.origin + route);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Aeria/);
  }
  assert.equal(
    (await a.call("/api/auth/demo-login", { role: "organizer" })).status,
    404,
  );
  assert.equal((await a.call("/api/cases")).status, 503);
  for (const route of ["authorize", "callback"])
    assert.equal(
      (await fetch(`${a.origin}/_api/auth/microsoft_login_${route}`)).status,
      503,
    );
  assert.equal(
    (
      await a.call("/_api/auth/microsoft_login_establish_session", {
        email: "claimed@uky.edu",
      })
    ).status,
    503,
  );
  assert.equal((await fetch(a.origin + "/data/aeria.db")).status, 404);
  assert.equal(
    (await (await fetch(a.origin + "/_api/auth/session")).json()).user,
    null,
  );
});

test("findings preserve exact source wording without inferring beyond the record", async (t) => {
  const a = await boot(t),
    record = await a.newAnalysis(await a.newCase());
  const data = (await a.call("/api/records/read", record)).body;
  assert.equal(data.policy.hash, sha256(data.policy.text));
  assert.match(data.policy.text, /^  Your application/);
  assert.match(
    data.analysis.scope,
    /Not documented in this source does not mean absent/,
  );
  assert.equal(data.analysis.method.model, null);
  assert.equal(data.analysis.findings[0].status, "PASSAGE_IDENTIFIED");
  assert.match(data.analysis.findings[0].passages[0].text, /denied because/);
  assert.equal(data.analysis.findings[2].status, "NOT_DOCUMENTED");
  assert.ok(
    data.analysis.findings.every(
      (f) => !["AVAILABLE", "COMPLIANT"].includes(f.status),
    ),
  );
  assert.equal(data.events.length, 2);
  assert.equal(verifyPacket(data).valid, true);
  const checked = (await a.call("/api/records/verify", record)).body;
  assert.equal(checked.valid, true);
  assert.equal(checked.recomputedReceiptHash, record.receiptHash);
});

test("offline verification detects source, finding, receipt, event and projection tampering", async (t) => {
  const a = await boot(t),
    record = await a.newAnalysis(await a.newCase());
  const original = (await a.call("/api/records/read", record)).body;
  const changes = [
    (p) => {
      p.policy.text += "Changed";
    },
    (p) => {
      p.policy.version = "v2";
    },
    (p) => {
      p.analysis.findings[0].status = "COMPLIANT";
    },
    (p) => {
      p.analysis.scope = "All policies";
    },
    (p) => {
      p.analysis.authorityBoundary = "AI may acknowledge";
    },
    (p) => {
      p.analysis.method.model = "undisclosed-model";
    },
    (p) => {
      p.analysis.timestamp = "2000-01-01";
    },
    (p) => {
      p.receipt.hash = "0".repeat(64);
    },
    (p) => {
      p.establishes = "Legal compliance is established";
    },
    (p) => {
      p.limitations = "None";
    },
    (p) => {
      p.events[0].actor.id = "someone-else";
    },
    (p) => {
      p.events.reverse();
    },
    (p) => {
      p.events.splice(0, 1);
    },
    (p) => {
      p.events.pop();
    },
    (p) => {
      p.sourcePassages[0].text = "altered";
    },
    (p) => {
      p.requestStates.push({ requestId: "invented", state: "ACKNOWLEDGED" });
    },
  ];
  for (const change of changes) {
    const altered = structuredClone(original);
    change(altered);
    assert.equal(verifyPacket(altered).valid, false);
  }
  assert.equal(verifyPacket({}).valid, false);
});

test("civilian keys and operator authority are checked independently; body roles cannot grant authority", async (t) => {
  const a = await boot(t),
    c = await a.newCase();
  assert.equal(
    (await a.call("/api/cases/read", { ...c, accessKey: "wrong" })).status,
    403,
  );
  assert.equal(
    (
      await a.call("/api/accesslayer/read", {
        caseId: c.caseId,
        role: "organizer",
      })
    ).status,
    401,
  );
  const request = (
    await a.call("/api/requests", { ...c, content: "Please arrange captions." })
  ).body;
  const data = {
    caseId: c.caseId,
    requestId: request.requestId,
    actor: { kind: "HUMAN_OPERATOR", id: "demo-organizer" },
  };
  assert.equal((await a.call("/api/requests/acknowledge", data)).status, 401);
  const auditor = await a.login("auditor");
  assert.equal(
    (await a.call("/api/requests/acknowledge", data, auditor)).status,
    403,
  );
  const organizer = await a.login("organizer");
  assert.equal(
    (
      await a.call("/api/requests/acknowledge", data, {
        Cookie: organizer.Cookie,
      })
    ).status,
    403,
  );
  assert.equal(
    (await a.call("/api/requests/acknowledge", data, organizer)).status,
    200,
  );
  assert.equal(
    (await a.call("/api/requests/acknowledge", data, organizer)).status,
    409,
  );
  const bundle = (await a.call("/api/cases/read", c)).body;
  assert.equal(bundle.events.at(-1).actor.id, "demo-organizer");
  assert.equal(bundle.requests[0].state, "ACKNOWLEDGED");
});

test("institution connection, membership, assignment and capability each gate access", async (t) => {
  const a = await boot(t),
    c = await a.newCase(),
    auth = await a.login("organizer");
  const read = () =>
    a.call("/api/accesslayer/read", { caseId: c.caseId }, auth);
  assert.equal((await read()).status, 200);
  a.db.prepare("UPDATE institutions SET connected=0").run();
  assert.equal((await read()).status, 401);
  a.db.prepare("UPDATE institutions SET connected=1").run();
  a.db.prepare("UPDATE members SET active=0 WHERE id=?").run("demo-organizer");
  assert.equal((await read()).status, 401);
  a.db.prepare("UPDATE members SET active=1 WHERE id=?").run("demo-organizer");
  a.db
    .prepare("DELETE FROM assignments WHERE case_id=? AND member_id=?")
    .run(c.caseId, "demo-organizer");
  assert.equal((await read()).status, 403);
  a.db
    .prepare("INSERT INTO assignments VALUES (?,?)")
    .run(c.caseId, "demo-organizer");
  a.db
    .prepare("INSERT INTO institutions VALUES (?,?,?)")
    .run("foreign", "Different institution", 1);
  a.db
    .prepare("UPDATE members SET institution_id=? WHERE id=?")
    .run("foreign", "demo-organizer");
  assert.equal((await read()).status, 403);
  a.db
    .prepare("UPDATE members SET institution_id=? WHERE id=?")
    .run("demo-institution", "demo-organizer");
  a.db
    .prepare("UPDATE members SET capabilities=? WHERE id=?")
    .run("[]", "demo-organizer");
  assert.equal((await read()).status, 403);
});

test("sessions use hashed opaque tokens, expire, rotate and revoke on logout; cross-origin writes are rejected", async (t) => {
  const a = await boot(t),
    c = await a.newCase();
  const auth = await a.login("organizer");
  const token = auth.Cookie.split("=")[1];
  assert.equal(
    a.db.prepare("SELECT token_hash FROM sessions").get().token_hash,
    sha256(token),
  );
  assert.equal(
    (await a.call("/api/cases", {}, { Origin: "https://other.example" }))
      .status,
    403,
  );
  const rotated = await a.call(
    "/api/auth/demo-login",
    { role: "organizer" },
    auth,
  );
  assert.match(rotated.headers.get("set-cookie"), /HttpOnly; SameSite=Strict/);
  assert.equal(
    (await a.call("/api/accesslayer/read", { caseId: c.caseId }, auth)).status,
    401,
  );
  const second = {
    Cookie: rotated.headers.get("set-cookie").split(";")[0],
    "X-CSRF-Token": rotated.body.csrf,
  };
  assert.equal((await a.call("/_api/auth/logout", {}, second)).status, 200);
  assert.equal(
    (await a.call("/api/accesslayer/read", { caseId: c.caseId }, second))
      .status,
    401,
  );
  const expired = await a.login("organizer");
  a.db.prepare("UPDATE sessions SET expires_at=0").run();
  assert.equal(
    (await a.call("/api/accesslayer/read", { caseId: c.caseId }, expired))
      .status,
    401,
  );
});

test("request deletion preserves receipt validity without content or content hashes in history or exports", async (t) => {
  const a = await boot(t),
    c = await a.newCase(),
    record = await a.newAnalysis(c);
  const secret = "SENSITIVE-CONTENT-DO-NOT-RETAIN-4927";
  const request = (await a.call("/api/requests", { ...c, content: secret }))
    .body;
  const exportedBefore = (await a.call("/api/records/export", record)).body;
  assert.ok(!JSON.stringify(exportedBefore).includes(secret));
  assert.ok(!JSON.stringify(exportedBefore).includes(sha256(secret)));
  assert.equal(exportedBefore.events.at(-1).type, "EVIDENCE_PACKET_EXPORTED");
  assert.equal(
    (
      await a.call("/api/requests/delete", {
        ...c,
        requestId: request.requestId,
      })
    ).status,
    200,
  );
  assert.equal(
    a.db.prepare("SELECT COUNT(*) AS count FROM request_content").get().count,
    0,
  );
  const bundle = (await a.call("/api/cases/read", c)).body;
  assert.equal(bundle.requests[0].content, null);
  assert.ok(!JSON.stringify(bundle).includes(secret));
  assert.deepEqual(bundle.events.at(-1).payload, {
    requestId: request.requestId,
  });
  const verified = (await a.call("/api/records/verify", record)).body;
  assert.equal(verified.valid, true);
  assert.equal(verified.recomputedReceiptHash, record.receiptHash);
  const count = bundle.events.length;
  await a.call("/api/requests/delete", { ...c, requestId: request.requestId });
  assert.equal((await a.call("/api/cases/read", c)).body.events.length, count);
});

test("case boundaries stop cross-case request transitions and receipt reads", async (t) => {
  const a = await boot(t),
    first = await a.newCase(),
    second = await a.newCase();
  const record = await a.newAnalysis(first);
  const request = (
    await a.call("/api/requests", { ...first, content: "Support" })
  ).body;
  assert.equal(
    (
      await a.call("/api/requests/delete", {
        ...second,
        requestId: request.requestId,
      })
    ).status,
    404,
  );
  assert.equal(
    (
      await a.call("/api/records/read", {
        ...second,
        analysisId: record.analysisId,
      })
    ).status,
    404,
  );
});

test("SQL prevents ordinary historical mutation and transactions roll back if event recording fails", async (t) => {
  const a = await boot(t),
    c = await a.newCase();
  await a.newAnalysis(c);
  for (const table of ["events", "policies", "analyses", "receipts"]) {
    assert.throws(() => a.db.exec(`DELETE FROM ${table}`), /append-only/);
    assert.throws(
      () => a.db.exec(`UPDATE ${table} SET body=body`),
      /append-only/,
    );
  }
  a.db.exec(
    "CREATE TRIGGER test_fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
  );
  assert.equal(
    (await a.call("/api/requests", { ...c, content: "Must roll back" })).status,
    500,
  );
  assert.equal(
    a.db.prepare("SELECT COUNT(*) AS count FROM requests").get().count,
    0,
  );
  assert.equal(
    a.db.prepare("SELECT COUNT(*) AS count FROM request_content").get().count,
    0,
  );
});

test("persisted source corruption is detected by Verify record and prevents packet export", async (t) => {
  const a = await boot(t),
    record = await a.newAnalysis(await a.newCase());
  // Simulate a privileged editor bypassing ordinary append-only restrictions.
  a.db.exec("DROP TRIGGER policies_no_UPDATE");
  const row = a.db.prepare("SELECT id,body FROM policies").get(),
    body = JSON.parse(row.body);
  body.text += " Tampering";
  a.db
    .prepare("UPDATE policies SET body=? WHERE id=?")
    .run(JSON.stringify(body), row.id);
  assert.equal((await a.call("/api/records/verify", record)).body.valid, false);
  assert.equal((await a.call("/api/records/export", record)).status, 409);
});

test("file persistence survives restart and secure deletion removes request bytes from active database", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "aeria-test-"));
  const filename = path.join(dir, "test.db");
  let db;
  try {
    db = openDatabase(filename);
    seedDemo(db);
    const c = createCase(db, "demo-institution"),
      actor = { kind: "HUMAN_CASE_HOLDER", id: c.caseId };
    const result = analyze(db, c.caseId, actor, {
      policyText: "A wheelchair ramp is documented.",
      policyVersion: "v1",
    });
    const secret = "PRIVATE-DELETION-BYTES-728134";
    const request = submitRequest(db, c.caseId, actor, secret);
    transitionRequest(db, c.caseId, request.requestId, actor, "delete");
    db.close();
    db = null;
    assert.equal(readFileSync(filename).includes(Buffer.from(secret)), false);
    db = openDatabase(filename);
    assert.equal(
      verifyPacket(packet(db, c.caseId, result.analysisId)).valid,
      true,
    );
  } finally {
    if (db) db.close();
    rmSync(dir, { recursive: true });
  }
});

test("malformed input receives validation errors without internal failures", async (t) => {
  const a = await boot(t);
  assert.equal((await a.call("/api/cases/read", {})).status, 400);
  assert.equal(
    (await a.call("/api/auth/demo-login", { role: "toString" })).status,
    400,
  );
  assert.equal(
    (await a.call("/api/records/verify", { caseId: "case" })).status,
    400,
  );
  const res = await fetch(a.origin + "/api/cases", {
    method: "POST",
    headers: { Origin: a.origin, "Content-Type": "application/json" },
    body: "{invalid",
  });
  assert.equal(res.status, 400);
  const media = await fetch(a.origin + "/api/cases", {
    method: "POST",
    headers: { Origin: a.origin, "Content-Type": "text/plain" },
    body: "{}",
  });
  assert.equal(media.status, 415);
});

test("standalone verifier accepts exported persisted records and returns failure for tampered files", async (t) => {
  const a = await boot(t),
    record = await a.newAnalysis(await a.newCase());
  const exported = (await a.call("/api/records/export", record)).body;
  const dir = mkdtempSync(path.join(tmpdir(), "aeria-cli-test-"));
  const filename = path.join(dir, "packet.json");
  const executable = fileURLToPath(
    new URL("../tools/verify-packet.mjs", import.meta.url),
  );
  try {
    writeFileSync(filename, JSON.stringify(exported));
    const valid = spawnSync(process.execPath, [executable, filename], {
      encoding: "utf8",
    });
    assert.equal(valid.status, 0, valid.stderr);
    assert.equal(JSON.parse(valid.stdout).valid, true);
    exported.policy.text += "Modified";
    writeFileSync(filename, JSON.stringify(exported));
    const invalid = spawnSync(process.execPath, [executable, filename], {
      encoding: "utf8",
    });
    assert.equal(invalid.status, 1);
    assert.equal(JSON.parse(invalid.stdout).valid, false);
  } finally {
    rmSync(dir, { recursive: true });
  }
});
