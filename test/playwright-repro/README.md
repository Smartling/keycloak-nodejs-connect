# AUT-1462 redirect-loop repro harness

Playwright harness that tries to trigger the intermittent "Too Many Redirects"
loop on stg, many times in a row, without needing a human to manually shrink
Keycloak session timeouts and babysit browser tabs each time.

Background: see `AUT-1461` / `AUT-1462` in Jira and the `#keycloak-dev` Slack
channel. Even with the fixes in `middleware/grant-attacher.js`,
`middleware/logout.js` and `middleware/post-auth.js`, the team can still
intermittently reproduce the loop on stg - this harness exists to make that
reproducible on demand instead of by luck.

## Scope: what this DOES and DOES NOT test

**Does:** exercises this repo's own `keycloak-connect` adapter code
(`index.js`, `middleware/*`) directly, end to end - real login against real
stg Keycloak, real session/token handling, real grant storage, through the
actual middleware chain (`Setup → PostAuth → Admin → GrantAttacher →
Logout → Protect`). The session-cap/redirect-loop bug we're chasing lives
entirely in this code, so testing it in isolation is sufficient to reproduce
and diagnose it.

**Does NOT (yet):** touch `tms-dashboard-app`, `ti-next`, `wa`, or any other
real Smartling product surface. `fixture-app/` is a bare-bones Express app
with one protected JSON route - it never calls TMS's backend, never checks
account/permission data, and has no dependency on whatever additional
provisioning (beyond the Keycloak identity itself) a real product login
would need. The throwaway test user this harness creates exists **only**
in Keycloak; it is not, and does not need to be, provisioned in TMS. This
is a deliberate choice to keep the reproduction focused on the adapter code
under test, not a limitation to work around - but it does mean this harness
cannot tell you whether the bug (or its fix) behaves the same way inside the
real dashboard app. If that ever becomes necessary, see
[`ROADMAP-dashboard.md`](./ROADMAP-dashboard.md) for a brief note on what
would need to change.

## How it works, briefly

1. `provision.js` creates a **throwaway OIDC client** in the stg Smartling
   realm (not the shared `tms-dashboard-app`/`ti-next`/`wa` clients) and
   overrides *only that client's* session/token lifetimes to ~60-120 seconds
   via the Advanced settings Keycloak exposes per-client. This forces the
   KC26 "session-cap" condition (see `grant-manager.js`'s `ensureFreshness`)
   to happen quickly, without touching the realm-wide SSO Session Max that
   every other stg user/client relies on.
2. `repro.js` spins up a small fixture Express app (`fixture-app/`) built on
   **this repo's own `index.js`/`middleware/*`** - the actual code being
   tested - logs in as a dedicated throwaway test user, waits past the
   session-cap window, and reloads a deep-linked protected URL repeatedly
   (optionally from two concurrent tabs, to target the multi-tab race shape
   both AUT-1461 and the suspected residual AUT-1462 issue share). It records
   a result row per iteration and keeps a Playwright trace + HAR only for
   iterations that actually reproduce the loop.

## One-time setup

Prerequisite: run `npm install` at the **repo root** first, under Node 16
(`nvm use`), if you haven't already for other work in this repo. The fixture
app requires `../../../index.js` directly and reuses `express`/
`express-session` from the root `node_modules` (both already root
devDependencies) rather than duplicating them here.

```bash
cd test/playwright-repro
npm install
cp .env.example .env
```

`repro.js` drives real installed **Google Chrome** (via Playwright's
`channel: 'chrome'`), not Playwright's bundled Chromium - the original bug
report is specifically about Chrome, so that's what this reproduces against.
This requires Chrome to already be installed on your machine (normal for a
dev laptop); if it isn't, either install it or run
`npx playwright install chromium` and switch `repro.js`'s `chromium.launch()`
call back to no `channel` option.

Fill in `.env`:
- `KC_ADMIN_USERNAME` / `KC_ADMIN_PASSWORD`: must be an admin account that
  exists **inside the `Smartling` realm itself** (i.e. shows up under
  Users when you have the Smartling realm selected in the admin console),
  with realm-management rights to create/update clients and users there -
  **not** a `master`-realm superadmin account. A master-realm account will
  fail with a generic "Invalid user credentials" error here even when the
  password is correct, because it doesn't exist in the Smartling realm's own
  user store (confirmed by direct testing - see `KC_ADMIN_REALM` below).
  Ask the team for the shared 1Password entry - don't use a personal stg
  login. **This harness never asks for or stores prod credentials or access.**
- `KC_TEST_PASSWORD`: leave blank and `provision.js` will generate one and
  print it once (it's also written to `.env` for you on first run).
- Everything else has a reasonable default; only change `KC_CLIENT_ID` if you
  want your own isolated throwaway client alongside a teammate's.

The fixture app needs to run under **Node 16** (this repo's pinned version,
see the root `CLAUDE.md`/`.nvmrc`), independent of whatever Node version you
use to run Playwright itself. If you have `nvm` with Node 16 installed
(`nvm install 16`), you don't need to do anything else - the harness resolves
it automatically. If that fails on your machine, set `FIXTURE_NODE_BINARY` in
`.env` to the absolute path of a Node 16 binary (e.g. `nvm which 16`).

## Safety model - read this before running anything

`provision.js` is **dry-run by default**. Without `--apply`, it authenticates
(read-only) and prints exactly what it *would* create/update/delete without
making any change. Nothing in the stg realm is touched until you explicitly
add `--apply`.

Every client/user this tool creates is tagged with a
`smartling.playwright-repro` attribute. If `KC_CLIENT_ID` or
`KC_TEST_USERNAME` happens to collide with something that already exists and
doesn't carry that tag, `provision.js` refuses to touch it (create, update,
*or* delete) and errors out instead - so a naming collision can never
silently modify or delete something real.

Even in dry-run mode, `provision.js` still makes one real (but read-only)
authenticated call to stg Keycloak with the admin credentials in `.env`, to
look up whether the client/user already exist. That's the only network
activity dry-run performs.

Both `provision.js` and `repro.js` also hard-fail immediately if
`KC_BASE_URL` doesn't look like a staging URL (i.e. doesn't contain "stg") -
this harness is scoped to stg only, and this check exists so a `.env` typo
can't point it at prod.

## Running it

```bash
# 1. See exactly what would be created, without touching stg
npm run provision:plan

# 2. Review that output, then actually create it
npm run provision:apply

# 3. Open the stg admin console (Clients -> playwright-repro-stg -> Advanced)
#    and cross-check the attributes provision.js printed against what's
#    actually there. Do this before running repro.js at scale.

# 4. Start small: one iteration, one tab, headed so you can watch it
node repro.js --iterations=1 --tabs=1 --headed

# 5. Once that looks right, run the real loop
node repro.js --iterations=50 --tabs=2
```

Results land in `results/results.json` (one JSON object per line - iteration
number, tab count, reproduced true/false, redirect-chain length, elapsed
time, final URL/error). Traces and HARs for iterations that **did** reproduce
the bug are saved under `results/traces/` and `results/har/` respectively;
non-reproducing iterations don't leave artifacts behind.

When you're done:

```bash
npm run teardown:plan    # see what would be deleted
npm run teardown:apply   # actually delete the throwaway client + user
```

## Sanity-checking the harness itself

Before trusting a run of "0/50 reproduced" against current `master`, first
confirm the harness can actually catch the bug: check out the commit just
before the AUT-1462 fix (`git log --oneline` to find the parent of `cbef5ad`)
in a separate worktree, point the fixture app at that checkout, and confirm
`repro.js` reliably reports `reproduced: true`. If it doesn't reproduce the
*known* old bug, don't trust it reporting "no repro" on current code either.

## Known defect found while building this harness

While getting a single iteration working, this harness surfaced a real,
confirmed bug in this repo's own code - independent of whether the redirect
loop itself reproduces:

**`ensureFreshness()` in `middleware/auth-utils/grant-manager.js` (around
line 173-176) omits `client_id` from the `refresh_token` grant request
body.** `postOptions()` only adds an `Authorization: Basic` header for
confidential clients (`if (!manager.public)`), so a **public** client's
refresh request carries neither that header nor `client_id` anywhere in the
payload - Keycloak has no way to identify the calling client and correctly
rejects it with `invalid_client`. Confirmed live: our throwaway harness
client failed every refresh with exactly this error while public; switching
it to confidential (see `provision.js`) made the identical flow work
immediately. `obtainDirectly()` elsewhere in the same file already includes
`client_id` in its params, so the fix is a one-line addition of
`client_id: this.clientId` to the `refresh_token` grant's `params` object,
matching that existing pattern.

This most likely hasn't surfaced in production because `tms-dashboard-app`/
`ti-next`/`wa` are presumably confidential clients, but it's a real
correctness bug in the library for anyone using this adapter with a public
client. Tracked as [AUT-1468](https://smartling.atlassian.net/browse/AUT-1468).

## Known unknowns (flagging rather than guessing)

Confirmed against the live stg KC26 admin console:
- The client attribute keys (`client.session.max.lifespan`,
  `client.session.idle.timeout`, `access.token.lifespan`) are correct -
  `provision.js`'s read-back after apply matched what the admin console
  showed under Clients → `<client>` → Advanced.
- The admin account must exist inside the `Smartling` realm itself, not
  `master` (see the setup section above) - confirmed by testing both.
- The Admin REST API (`/admin/realms/*`) is only reachable via the internal
  `KC_ADMIN_BASE_URL` hostname; the public `KC_BASE_URL` hostname returns a
  network-level 403 for every `/admin/*` path regardless of credentials.
- The login form is a two-step identifier-first flow, confirmed by live
  inspection (screenshot + DOM dump): the email field (`#username`, HTML
  `type="email"` with native browser validation) is submitted first via
  `#kc-login`, which reveals the password field - also submitted via the
  same `#kc-login` selector. `login()` handles this now. This is also why
  `KC_TEST_USERNAME` must be email-shaped (see `.env.example`) - a plain
  username can never even be submitted past step one, regardless of what
  Keycloak itself would accept.

Still open:
- Whether a per-client session override actually reaches the same
  "remaining session time" calculation `ensureFreshness()` reads, versus only
  a realm-wide SSO Session Max doing so. The sanity-check section above is
  what confirms or refutes this once a full iteration completes end-to-end.
