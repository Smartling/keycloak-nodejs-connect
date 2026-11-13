'use strict';

// Minimal Express app built on THIS repo's own keycloak-connect code (not
// tms-dashboard-app), so the harness exercises the exact middleware under
// test rather than adding unrelated frontend flakiness. Deliberately spawned
// as its own process under Node 16 - see lib/spawn-fixture-app.js for why.

const path = require('path');
const express = require('express');
const session = require('express-session');
const Keycloak = require(path.join(__dirname, '..', '..', '..', 'index'));

const PORT = Number(process.env.FIXTURE_APP_PORT || 3987);

const keycloakConfig = {
  realm: process.env.KC_REALM,
  'client-id': process.env.KC_CLIENT_ID,
  // Confidential, not public: ensureFreshness()'s refresh_token request
  // (grant-manager.js) relies on the Authorization: Basic header
  // postOptions() only adds for confidential clients - a public client's
  // refresh fails with "invalid_client" (confirmed live). Also more
  // faithful to production, where real clients are presumably confidential.
  'public-client': false,
  credentials: { secret: process.env.KC_CLIENT_SECRET },
  'auth-server-url': process.env.KC_BASE_URL,
  'ssl-required': 'external',
  // Mirrors production's tokenMinTtl so the session-cap detection in
  // grant-manager.js's ensureFreshness() fires the same way it does there,
  // just against a much shorter session window (see provision.js).
  'token-minimum-time-to-live': Number(process.env.KC_TOKEN_MIN_TTL_SECONDS || 20)
};

const app = express();
const memoryStore = new session.MemoryStore();

app.use(session({
  secret: 'playwright-repro-not-for-production',
  resave: false,
  saveUninitialized: true,
  store: memoryStore
}));

const keycloak = new Keycloak({ store: memoryStore }, keycloakConfig);

app.use(keycloak.middleware({
  logout: '/logout',
  admin: '/'
}));

app.get('/', (request, response) => {
  response.send('fixture app ok (not authenticated route)');
});

// Deep-linked protected route, mirroring the query-param-bearing URLs from
// the real bug reports (e.g. /app/<accountId>?locale=fr&start=0&...) - the
// AUT-1462 14fb4ee fix is specifically about preserving this shape through
// the logout/redirect cycle, so the repro harness needs to hit it.
app.get('/app/:accountId', keycloak.protect(), (request, response) => {
  const accessToken = request.kauth.grant.access_token.content;
  response.json({
    ok: true,
    accountId: request.params.accountId,
    query: request.query,
    tokenExp: accessToken.exp,
    tokenIat: accessToken.iat,
    issuedLifetime: accessToken.exp - accessToken.iat
  });
});

app.listen(PORT, () => {
  // lib/spawn-fixture-app.js waits for this exact marker on stdout.
  console.log(`FIXTURE_APP_READY port=${PORT}`);
});
