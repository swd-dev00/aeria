const app = document.querySelector("#app"),
  notice = document.querySelector("#notice");
let session,
  activeCase = null,
  key = null;
let csrf = sessionStorage.getItem("aeria-csrf");
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
async function api(url, body) {
  const response = await fetch(
    url,
    body === undefined
      ? { credentials: "same-origin" }
      : {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            ...(csrf ? { "X-CSRF-Token": csrf } : {}),
          },
          body: JSON.stringify(body),
        },
  );
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Operation failed.");
  return result;
}
function bind(selector, event, fn) {
  document.querySelector(selector)?.addEventListener(event, async (e) => {
    e.preventDefault();
    notice.textContent = "";
    const button =
      e.submitter ||
      (e.currentTarget.tagName === "BUTTON" ? e.currentTarget : null);
    if (button) button.disabled = true;
    try {
      await fn(e);
    } catch (error) {
      notice.textContent = error.message;
    } finally {
      if (button) button.disabled = false;
    }
  });
}
const credentials = () => ({
  caseId: activeCase,
  ...(key ? { accessKey: key } : {}),
});
function home() {
  app.innerHTML = `<p class="eyebrow">Aeria / private evidence record</p><h1>Keep the record of what actually happened.</h1><p class="lede">Preserve the decision you received, inspect the exact passages behind each finding, request missing institutional records, and keep human actions distinct from automated analysis.</p><a class="button" href="/workspace">Open workspace</a><div class="grid"><section class="panel"><h2>Bounded findings</h2><p>Every finding applies only to the supplied source record. “Not documented here” never means the institution has no other record.</p></section><section class="panel"><h2>Inspectable records</h2><p>Recompute receipt hashes, inspect human actions, and export source-backed evidence for your own review.</p></section></div>`;
}
function governance() {
  app.innerHTML = `<p class="eyebrow">Record boundaries</p><h1>Evidence with explicit limits.</h1><section class="panel"><h2>Source → finding → boundary → authority → event → receipt</h2><p>The current method is deterministic passage extraction, not a language model. Matching words identify passages for review; they do not establish correctness, intent, remedy, or legal compliance.</p><p>Only the case holder submits a record request. Only a separately authenticated and assigned institution operator with acknowledgement permission records acknowledgement. A packet export does not initiate escalation or contact anyone.</p></section><section class="panel"><h2>What verification establishes</h2><p>Verify record reconstructs a canonical SHA-256 receipt from persisted policy text, findings, method, scope, authority boundary, version and timestamp. It checks source passages and the event chain. Exported JSON can also be checked offline.</p><p>Database triggers prevent ordinary edits or deletes to history. This is application-level append-only storage, not physical immutability. No external anchor or trusted timestamp is configured. A privileged administrator could rewrite the database and recompute its hashes.</p></section><section class="panel"><h2>Request deletion</h2><p>Request content is separate from history and receipts. Deletion leaves an opaque request ID, prior transitions and the fact of deletion. Exports omit request text entirely. SQLite secure deletion is enabled; backups, snapshots, previously downloaded files and copies held by others remain outside this operation.</p></section>`;
}
function login() {
  app.innerHTML = `<p class="eyebrow">Institutional access</p><h1>Operator session</h1><section class="panel"><p>${session.user ? `Signed in as ${escape(session.user.name)}.` : "No institutional session."}</p><p>Microsoft sign-in has not been reconstructed or configured. A claimed email domain does not grant institutional authority.</p>${session.demo ? `<form id="demo-login"><label for="role">Synthetic institution role</label><select id="role"><option value="organizer">Caseworker - acknowledge assigned record requests</option><option value="auditor">Auditor - read and export only</option></select><button>Enter local demo</button></form><p class="small">Demo roles do not verify real-world identity. Use synthetic data only.</p>` : "<p>Run <code>npm run demo</code> to explore the synthetic environment.</p>"}${session.user ? '<button id="logout" class="secondary">Sign out</button>' : ""}</section>`;
  bind("#demo-login", "submit", async () => {
    const result = await api("/api/auth/demo-login", {
      role: document.querySelector("#role").value,
    });
    csrf = result.csrf;
    sessionStorage.setItem("aeria-csrf", csrf);
    location.href = "/workspace";
  });
  bind("#logout", "click", async () => {
    await api("/_api/auth/logout", {});
    sessionStorage.removeItem("aeria-csrf");
    location.reload();
  });
}
function workspace() {
  app.innerHTML = `<p class="eyebrow">Private case workspace</p><h1>Start with the decision you received.</h1><p>Preserve the source record exactly as received. Keep unnecessary personal information out of demo records: source snapshots are retained as evidence.</p><div class="grid"><section class="panel"><h2>Create a case</h2><p>Save the private access key when shown. It cannot be recovered here.</p><button id="create" ${session.demo ? "" : "disabled"}>Create synthetic evidence case</button></section><section class="panel"><h2>Reopen a case</h2><form id="reopen"><label for="case-id">Case ID</label><input id="case-id" required autocomplete="off"><label for="case-key">Private access key</label><input id="case-key" type="password" required autocomplete="off"><button>Open case</button></form></section></div>${session.user ? '<section class="panel"><h2>Assigned institutional cases</h2><div id="assigned"></div></section>' : '<p><a href="/login">Sign in as a demo institution operator</a> to review assigned cases and acknowledge requests.</p>'}<div id="case"></div>`;
  bind("#create", "click", async () => {
    const result = await api("/_api/civilian-case-v2", {});
    activeCase = result.caseId;
    key = result.accessKey;
    await refreshCase();
    notice.textContent = `Save these credentials now. Case: ${activeCase}\nPrivate key: ${key}`;
    if (session.user) await loadAssigned();
  });
  bind("#reopen", "submit", async () => {
    activeCase = document.querySelector("#case-id").value.trim();
    key = document.querySelector("#case-key").value.trim();
    document.querySelector("#case-key").value = "";
    await refreshCase();
  });
  if (session.user)
    loadAssigned().catch((e) => {
      notice.textContent = e.message;
    });
}
async function loadAssigned() {
  const { cases } = await api("/_api/accesslayer-cases", {}),
    target = document.querySelector("#assigned");
  target.textContent = cases.length
    ? ""
    : "No assigned cases yet. Create a synthetic case above.";
  for (const item of cases) {
    const button = document.createElement("button");
    button.className = "secondary";
    button.textContent = item.id;
    button.addEventListener("click", async () => {
      activeCase = item.id;
      key = null;
      notice.textContent = "";
      try {
        await refreshCase();
      } catch (e) {
        notice.textContent = e.message;
      }
    });
    target.append(button);
  }
}
async function refreshCase() {
  const context = credentials();
  document.querySelector("#case").textContent = "Loading case…";
  const bundle = await api(
    key ? "/_api/civilian-case-v2-read" : "/_api/accesslayer-case-read",
    context,
  );
  if (activeCase !== context.caseId || (key || undefined) !== context.accessKey)
    return;
  const canAnalyze = key || session.user?.capabilities.includes("ANALYZE");
  document.querySelector("#case").innerHTML =
    `<section class="panel"><h2>Case <span class="hash">${escape(activeCase)}</span></h2><p class="small">${key ? "Participant access key" : "Institutional session"} · record requests stored locally</p>${canAnalyze ? '<form id="analyze"><label for="version">Source label or document version</label><input id="version" required maxlength="120" value="supplied-v1"><label for="policy">Supplied source record</label><textarea id="policy" required maxlength="100000"></textarea><button>Preserve and analyze source</button><button id="fixture" type="button" class="secondary">Load synthetic policy</button></form>' : "<p>Read-only access to analyses.</p>"}</section><div id="analyses"></div><section class="panel"><h2>Missing institutional records</h2><p>Request a specific missing record, timestamp, notice, or decision artifact. Request text stays out of immutable history and exports.</p>${key ? '<form id="request"><label for="support">Requested institutional record</label><textarea id="support" required maxlength="5000"></textarea><button>Submit record request to this case</button></form>' : ""}<div id="requests"></div></section><section class="panel"><h2>Governance history</h2><div id="events"></div></section>`;
  bind("#fixture", "click", () => {
    document.querySelector("#policy").value =
      "Your application was denied because it was received after the 5:00 PM deadline. You may request reconsideration by contacting the review office. This notice cites the institution submission policy.";
  });
  bind("#analyze", "submit", async () => {
    await api("/_api/aeria-case-review", {
      ...credentials(),
      policyText: document.querySelector("#policy").value,
      policyVersion: document.querySelector("#version").value,
    });
    await refreshCase();
    notice.textContent =
      "Source analysis and canonical receipt recorded. No institutional request was acknowledged or escalated.";
  });
  bind("#request", "submit", async () => {
    const result = await api("/_api/civilian-record-request", {
      ...credentials(),
      content: document.querySelector("#support").value,
    });
    await refreshCase();
    notice.textContent = result.boundary;
  });
  for (const analysis of bundle.analyses) {
    const section = document.createElement("section");
    section.className = "panel";
    section.innerHTML = `<h2>Source analysis</h2><p>${escape(analysis.scope)}</p><p class="small">${escape(analysis.authorityBoundary)}</p><p class="small">Deterministic passage extraction v1 · no model · ${escape(analysis.timestamp)}</p>${analysis.findings.map((f) => `<article><h3>${escape(f.label)} · <span class="status">${f.status === "NOT_DOCUMENTED" ? "Not documented in this source" : "Related passage identified"}</span></h3>${f.passages.map((p) => `<blockquote>${escape(p.text)}</blockquote><p class="small">Source <span class="hash">${escape(p.sourceHash)}</span> · offsets ${p.start}–${p.end}</p>`).join("")}<p class="small">${escape(f.boundary)}</p></article>`).join("")}<button class="verify">Verify record</button><button class="export secondary">Export evidence packet</button><p class="result hash" role="status"></p>`;
    for (const action of ["verify", "export"])
      section
        .querySelector(`.${action}`)
        .addEventListener("click", async (e) => {
          const button = e.currentTarget;
          button.disabled = true;
          try {
            const data = await api(`/api/records/${action}`, {
              ...credentials(),
              analysisId: analysis.id,
            });
            if (action === "verify")
              section.querySelector(".result").textContent =
                `${data.valid ? "Verified against persisted data" : "Verification failed"} · ${data.recomputedReceiptHash || data.issues.join(", ")}. ${data.limitations}`;
            else {
              const url = URL.createObjectURL(
                  new Blob([JSON.stringify(data, null, 2)], {
                    type: "application/json",
                  }),
                ),
                link = document.createElement("a");
              link.href = url;
              link.download = `aeria-${analysis.id}.json`;
              link.click();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
              await refreshCase();
              notice.textContent =
                "Packet exported. No escalation initiated or recipient contacted.";
            }
          } catch (error) {
            section.querySelector(".result").textContent = error.message;
          } finally {
            button.disabled = false;
          }
        });
    document.querySelector("#analyses").append(section);
  }
  for (const request of bundle.requests) {
    const div = document.createElement("div");
    div.className = "event";
    div.innerHTML = `<p><span class="hash">${escape(request.id)}</span> · ${escape(request.state)}</p><p>${request.content === null ? "Request content deleted." : escape(request.content)}</p>`;
    const action = key
      ? request.state !== "CONTENT_DELETED"
        ? "delete"
        : null
      : request.state === "SUBMITTED" &&
          session.user?.capabilities.includes("ACKNOWLEDGE")
        ? "acknowledge"
        : null;
    if (action) {
      const button = document.createElement("button");
      button.className = "secondary";
      button.textContent =
        action === "delete"
          ? "Delete request content"
          : "Acknowledge as institution operator";
      button.addEventListener("click", async () => {
        if (
          action === "delete" &&
          !confirm(
            "Delete request content? Only its ID, prior transitions and the deletion fact remain.",
          )
        )
          return;
        button.disabled = true;
        try {
          await api(`/api/requests/${action}`, {
            ...credentials(),
            requestId: request.id,
          });
          await refreshCase();
        } catch (e) {
          notice.textContent = e.message;
          button.disabled = false;
        }
      });
      div.append(button);
    }
    document.querySelector("#requests").append(div);
  }
  document.querySelector("#events").innerHTML = bundle.events
    .map(
      (e) =>
        `<div class="event"><strong>${e.sequence}. ${escape(e.type)}</strong><br><span class="small">${escape(e.actor.kind)} · ${escape(e.actor.id)} · ${escape(e.timestamp)}</span><br><span class="hash">${escape(e.hash)}</span></div>`,
    )
    .join("");
}
try {
  session = await api("/_api/auth/session");
  document.querySelector("#mode").textContent = session.demo
    ? "Synthetic local demo · no legal compliance determination · no external delivery"
    : "Local reconstruction · identity provider not configured";
  (
    ({
      "/": home,
      "/workspace": workspace,
      "/login": login,
      "/governance": governance,
    })[location.pathname] || home
  )();
} catch (error) {
  notice.textContent = error.message;
}
