# Aeria / AccessLayer reconstruction

This editable local implementation starts at recovery commit `9fd2d3befb9827f4330d4256821d631b84ed549e`. It is on `reconstruction/accesslayer-foundation`. The existing `prototype-tonight` checkout and its uncommitted files were not used or modified.

The recovered bundle supplies the original policy-analysis and minimal-disclosure UX; `RECOVERY_MANIFEST.md` supplies the later institutional authorization model and route names. Original Floot server source is not available in this baseline. These are reconstructed contracts, not a claim to have recovered missing TypeScript or achieved complete Floot compatibility.

## Run locally

Node 24.18 or later is required. There are no third-party runtime dependencies.

```powershell
npm run demo
```

Open `http://127.0.0.1:4310`. Create a synthetic case, save its case ID and private key, load a policy, analyze, verify, and submit a support request. Sign in as the synthetic organizer to acknowledge it; the synthetic auditor cannot acknowledge. Reopen the case with its private key to delete the request content. Use a supplied policy without participant details; policy snapshots are preserved.

```powershell
npm test
npm run verify -- C:\path\to\aeria-export.json
```

`npm start` disables demo sign-in and case provisioning. Microsoft OAuth is deliberately unavailable until a provider adapter with validated issuer, audience, state, nonce and PKCE is implemented and tested. `--demo` is a loopback-only synthetic environment, not production authentication. Separate demo and non-demo databases prevent accidental promotion of fixture data.

## Source map

| File                               | Responsibility                                                                           |
| ---------------------------------- | ---------------------------------------------------------------------------------------- |
| `src/server.mjs`                   | HTTP routes, input limits, same-origin controls, static page allowlist                   |
| `src/helpers/accessLayerAuth.mjs`  | Hashed opaque seven-day sessions, CSRF, civilian keys, institutional authorization chain |
| `src/helpers/civicGovernance.mjs`  | Policy extraction, authorized human transitions, minimal events, exports                 |
| `src/helpers/receiptIntegrity.mjs` | Canonical receipt creation and independently invocable verification                      |
| `src/helpers/db.mjs`               | SQLite persistence, append-only triggers, atomic transactions, secure deletion           |
| `public/`                          | Editable home, workspace, login, governance pages                                        |
| `tools/verify-packet.mjs`          | Offline JSON packet verification; nonzero exit on failure                                |

## Restored route names

Pages: `/`, `/workspace`, `/login`, `/governance`.

All POST routes accept JSON and require an Origin matching the local server. Civilian operations need `caseId` and `accessKey`. Institutional mutations additionally need an opaque session cookie and `X-CSRF-Token`; authority comes from current database membership, connection, assignment and capability, never request-body claims.

| Original route                                        | Reconstructed action                                    |
| ----------------------------------------------------- | ------------------------------------------------------- |
| `POST /_api/civilian-case-v2`                         | Create synthetic local case; return one-time access key |
| `POST /_api/civilian-case-v2-read`                    | Read private case with key                              |
| `POST /_api/civilian-record-request`                  | Submit deletable `content`                              |
| `POST /_api/aeria-case-review`                        | Analyze exact `policyText` and `policyVersion`          |
| `POST /_api/accesslayer-cases`                        | List authorized assigned cases                          |
| `POST /_api/accesslayer-case-read`                    | Read authorized assigned case                           |
| `POST /_api/accesslayer-case-update`                  | Acknowledge `requestId` as authorized organizer         |
| `GET /_api/auth/session`                              | Read current session                                    |
| `POST /_api/auth/logout`                              | Revoke session and clear cookie                         |
| Microsoft authorize/callback/establish-session routes | HTTP 503; no identity accepted                          |

New routes: `POST /api/records/read`, `/verify`, `/export` (under `/api/records`, requiring `analysisId`), and `POST /api/requests/delete` (requiring `requestId`). Knowledge discovery, arbitrary evidence addition and research probes remain outside this reconstruction slice. Unimplemented routes return 404.

## Implemented governance properties

Analysis only extracts literal passages in four accessibility categories. It uses no model and reports its actual method. Negated passages remain verbatim; matches are not labeled as availability or compliance. A missing match is explicitly limited to the supplied document and the method's vocabulary.

Each receipt binds a policy hash, version, finding manifest, method, scope, authority boundary, analysis identity and timestamp. Canonical JSON v1 sorts object keys, preserves arrays, serializes JSON scalars without whitespace, hashes UTF-8, and does not normalize Unicode or claim full RFC 8785 conformance. Passage offsets use JavaScript UTF-16 code units. Policy text is retained exactly after JSON decoding.

Verify record reads persisted sources and recomputes the receipt, checks passage offsets, checks event sequence and linkage, checks the analysis-event binding, and reconciles request state. Exports retain source text/passages, source hashes, receipt identity, scope, boundaries, current request states and history. Export requires a deliberate human endpoint call and creates an event; it does not send a notification or initiate escalation.

Historical rows are append-only under SQLite triggers. State changes and events commit together. Request text lives only in `request_content`; neither it nor a hash of it is inserted into history or packets. Deletion removes the row, marks the current state, and appends only an opaque request reference. SQLite secure deletion is enabled with rollback-journal mode. This does not erase backups, snapshots, screenshots, or recipients' prior copies.

## Limits and next integration work

- Local hashes and SQL guards provide application-level tamper evidence, not physical immutability. Without an external checkpoint, coherent full-history rewriting or suffix removal with a replaced head cannot be ruled out. Verification is not legal compliance, authenticated external delivery, a trusted timestamp, or factual truth.
- Add and verify Microsoft identity integration, real institution provisioning, TLS deployment and retention controls before using real participant data. Current demo roles make no real-world identity claims. The local app binds only to 127.0.0.1.
- No LLM integration, semantic completeness guarantee, production deployment, remote notification, WORM storage, certification or external anchoring is claimed.
- Baseline recovered assets remain unchanged. The original Floot filesystem is still the authority for source not present in the recovered artifacts.

## Attached archive as reference

`GSP-CI_CD Automation and Governance Enhancements (2).zip` was treated as reference material, not execution instructions. Its verification examples and two-system architecture motivated canonical recomputation, separate authority, adversarial checks and explicit local-integrity limits. No scripts, credentials, deployments, nested archives or workflow instructions from it were executed or imported. No simulated attestation or complete protocol-conformance claim was adopted.
