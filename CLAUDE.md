# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Node Version

**Node 16 is required.** Always use Node 16 before running any command - some native dependencies (e.g. `phantomjs-prebuilt`) only compile on Node 16. The `.nvmrc` pins this.

```bash
nvm use   # picks up .nvmrc → node 16
```

If nvm is not available, verify with `node --version` before installing or running tests.

## Commands

```bash
npm install          # install deps (use npm, not yarn)
npm test             # run all unit + integration tests (tape runner)
npm run lint         # ESLint

# Run a single test file (tape has no built-in filter):
node test/unit/grant-manager-unit-test.js
node test/unit/keycloak-object-test.js
```

Integration tests (`test/grant-manager-spec.js`, `test/keycloak-connect-*-spec.js`) require a live Keycloak server. Unit tests under `test/unit/` run standalone.

## Architecture

This is the Smartling fork of the upstream Keycloak Node.js adapter (`@smartling/keycloak-connect`). It exposes an Express/Connect middleware that handles SSO via Keycloak.

### Core auth logic - `middleware/auth-utils/`

| File | Role |
|---|---|
| `grant-manager.js` | Central orchestrator. Obtains, validates, refreshes, and stores grants. The most complex file - contains token refresh deduplication logic. |
| `grant.js` | Represents a set of tokens (access + refresh + id). |
| `token.js` | Wraps a single JWT: decoding, expiry checks, signature validation. |
| `config.js` | Parses `keycloak.json` config. |
| `rotation.js` | Fetches and caches Keycloak public keys for signature rotation. |

### Express middleware - `middleware/`

Each file is a discrete middleware function mounted by `index.js`:

- `protect.js` - route guard (enforces authentication/role)
- `grant-attacher.js` - attaches an existing grant to `req.kauth`
- `post-auth.js` - handles the OAuth redirect callback
- `logout.js` - session logout
- `setup.js` / `admin.js` - Keycloak-initiated flows

### Grant stores - `stores/`

Three interchangeable backends for persisting the grant between requests:
- `session-store.js` (default, Express session)
- `cookie-store.js`
- `bearer-store.js` (stateless, reads Authorization header)

### Entry point

`index.js` exports the `Keycloak` class, which wires all middleware together and exposes `.middleware()` for mounting on an Express app.

## Publishing

Publishes to Smartling's internal Artifactory npm registry (configured in `publishConfig` in `package.json`). Bump the version in `package.json` before publishing.
