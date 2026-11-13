# Roadmap: extending this harness to `tms-dashboard-app` / `ti-next`

Brief notes on what would change if this harness needed to test the real
product surface instead of the isolated `fixture-app/` (see README.md
"Scope" section for why it doesn't today). Not a commitment to build this -
just what's known so it doesn't need to be re-derived later.

1. **Target app.** Point the Playwright browser flow at a running
   `tms-dashboard-app` (or `ti-next`) instance instead of `fixture-app/`.
   Either a local dev instance of that app pointed at stg Keycloak, or the
   real stg deployment - these have different tradeoffs (see point 3).

2. **TMS-side account provisioning.** A real dashboard login needs more than
   a Keycloak identity - per the checkpoint discussion in this session, the
   product likely needs a corresponding account record in TMS's own backend
   (accountUid, permissions, etc.) that a Keycloak-only user created by
   `provision.js` won't have. Cheapest path: reuse an existing, already-
   working stg test account (Keycloak + TMS both provisioned) rather than
   trying to script that provisioning here. Whoever owns that provisioning
   flow (ask in `#keycloak-dev`) would know if there's a supported way to
   create one from scratch.

3. **Session/token overrides can't be isolated the same way.**
   `provision.js`'s whole approach depends on a throwaway client whose
   session/token lifetimes we can shrink without affecting anyone else. The
   real `tms-dashboard-app`/`ti-next`/`wa` clients are shared production
   configuration - shrinking their overrides would affect every real stg
   user, the exact coordination cost this harness was built to avoid (see
   the 6/29-6/30 Slack history in `#keycloak-dev` about restoring shared
   session settings afterward). Two options, not mutually exclusive:
   - Run a local dev instance of the target app registered as its own
     throwaway client (same isolation model as `fixture-app/`), or
   - Coordinate a short, announced window to shrink the real shared client's
     overrides, as the team has done manually before.

4. **Login flow should mostly transfer.** The two-step identifier-first
   login theme and the Tab-blur requirement discovered while building this
   harness (see `repro.js`'s `login()`) are realm-level (Smartling realm),
   not client-specific - they should apply the same way against
   `tms-dashboard-app`/`ti-next`'s login pages.

5. **Deep-linked protected routes.** `fixture-app/`'s `/app/:accountId`
   route already loosely mirrors the real shape
   (`/app/<accountId>?locale=fr&start=0&...`) reported in the original bug.
   Swapping in the actual dashboard route(s) that showed the loop should be
   straightforward once points 1-3 are settled.
