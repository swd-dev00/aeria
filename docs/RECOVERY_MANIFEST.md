# Aeria Codex Recovery Manifest

This workspace is for the original Aeria application built in Floot.
It is NOT the Manus rebuild and it is NOT AIREA.ai.

## Original Floot project
- Project: Aeria
- Floot project ID: eb36b119-d68e-48d7-94a2-86e8dc9ac658
- Original production host: https://accesslayer-lexhack.floot.app
- Floot framework version: 3
- Database: Floot Postgres
- Authentication: JWT + Floot Microsoft Login
- Source of truth until local reconstruction is complete: Floot project filesystem

## Product boundaries
1. Aeria: civilian-facing private case product.
2. AccessLayer: authenticated institutional/government operator layer on the same Aeria cases.
3. Research Instrument: separate longitudinal AI observation surface.
4. AIREA.ai is a different project and must not be merged into Aeria.

## Original pages
- pages/_index.tsx
- pages/workspace.tsx
- pages/login.tsx
- pages/governance.tsx

## Original core helpers
- helpers/accessLayerAuth.tsx
- helpers/aeriaCaseReview.tsx
- helpers/civicGovernance.tsx
- helpers/civilianCaseAccess.tsx
- helpers/knowledge.tsx
- helpers/receiptIntegrity.tsx
- helpers/getSetServerSession.tsx
- helpers/getServerUserSession.tsx
- helpers/useAuth.tsx
- helpers/schema.tsx
- helpers/db.tsx

## Original key endpoints
- civilian-case-v2_POST
- civilian-case-v2-read_POST
- civilian-case-add_POST
- civilian-record-request_POST
- knowledge-discover_POST
- knowledge-attach_POST
- accesslayer-cases_POST
- accesslayer-case-read_POST
- accesslayer-case-update_POST
- research-probe_POST
- aeria-case-review_POST
- auth/session_GET
- auth/logout_POST
- auth/microsoft_login_authorize_GET
- auth/microsoft_login_callback_GET
- auth/microsoft_login_establish_session_POST

## Knowledge authority classes
- OFFICIAL_PRIMARY
- OFFICIAL_GOVERNMENT
- GOVERNMENT_INFORMATIONAL
- INSTITUTIONAL_PUBLIC
- SCHOLARLY_METADATA
- RESEARCH_REPOSITORY
- GENERAL_PUBLIC

## Known state before migration
- Civilian v2 cases require case ID + private access key.
- AccessLayer authorization chain: institution connection -> membership -> case assignment -> capability.
- Approved .edu domain demo path exists for University of Kentucky / uky.edu.
- Knowledge acquisition supports Federal Register, Crossref, DataCite and direct public URLs.
- Knowledge snapshots are hashed and preserved.
- Receipts use canonicalized SHA-256 integrity chaining.
- Microsoft auth required oauth_accounts; missing table was added.
- JWT lifetime was aligned to the intended 7-day session.
- Same-origin credentials were added to session establishment/session reads.
- Source-grounded claim reasoning was the next major feature, not yet implemented.

## Known defects / cleanup
- The latest Floot preview currently fails before render.
- Post-fix Microsoft login round-trip was not reverified after oauth_accounts creation.
- Some stale LexHack strings remain in old dormant files/internal docs.
- Published production is an older snapshot and does not contain the latest knowledge/auth work.
- Do not change production domain or publish without explicit approval.

## Recovery artifacts
recovered-build/ contains the exact published frontend bundle and route CSS recovered from the original Floot deployment. Treat these as reference artifacts, not editable source.

## Migration rule
Do not substitute Manus code for missing Floot source.
Do not import AIREA.ai internals wholesale.
Reconstruct original Aeria behavior first, then continue feature work.
