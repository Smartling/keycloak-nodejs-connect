'use strict';

const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const REQUIRED = [
  'KC_BASE_URL',
  'KC_ADMIN_BASE_URL',
  'KC_REALM',
  'KC_ADMIN_USERNAME',
  'KC_ADMIN_PASSWORD',
  'KC_ADMIN_CLIENT_ID',
  'KC_CLIENT_ID',
  'KC_TEST_USERNAME'
];

function requireEnv () {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) {
    throw new Error(
      `Missing ${envPath}.\n` +
      'Copy .env.example to .env and fill in stg Keycloak admin credentials before running this.'
    );
  }

  const missing = REQUIRED.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required .env values: ${missing.join(', ')}.\n` +
      'See .env.example for what each one means.'
    );
  }

  return {
    // Public hostname - serves OIDC login endpoints only (/realms/*/protocol/*)
    // and is what the fixture app / Playwright's browser actually talks to,
    // matching what real users see.
    kcBaseUrl: process.env.KC_BASE_URL,
    // Internal hostname - the ONLY place the Admin REST API (/admin/realms/*)
    // is reachable. The public hostname returns a network-level 403 (HTML,
    // not a Keycloak JSON error) for every /admin/* path regardless of
    // credentials - confirmed by testing directly, not assumed. Only
    // provision.js uses this.
    kcAdminBaseUrl: process.env.KC_ADMIN_BASE_URL,
    kcRealm: process.env.KC_REALM,
    kcAdminUsername: process.env.KC_ADMIN_USERNAME,
    kcAdminPassword: process.env.KC_ADMIN_PASSWORD,
    kcAdminClientId: process.env.KC_ADMIN_CLIENT_ID,
    // Keycloak admin accounts commonly live in the "master" realm even when
    // managing a different realm's clients/users - that's the SDK default,
    // made explicit and overridable here since it's a common source of
    // 401/403s if this admin account instead lives in KC_REALM itself.
    kcAdminRealm: process.env.KC_ADMIN_REALM || 'master',

    kcClientId: process.env.KC_CLIENT_ID,
    // Not in REQUIRED - provision.js's first run creates the client and
    // fetches this itself, so it can't already exist yet at that point.
    // repro.js checks for it separately before starting (see main()).
    kcClientSecret: process.env.KC_CLIENT_SECRET || '',
    kcTestUsername: process.env.KC_TEST_USERNAME,
    kcTestPassword: process.env.KC_TEST_PASSWORD || '',

    fixtureAppPort: Number(process.env.FIXTURE_APP_PORT || 3987),
    fixtureNodeBinary: process.env.FIXTURE_NODE_BINARY || '',

    clientSessionMaxSeconds: Number(process.env.KC_CLIENT_SESSION_MAX_SECONDS || 90),
    clientSessionIdleSeconds: Number(process.env.KC_CLIENT_SESSION_IDLE_SECONDS || 120),
    accessTokenLifespanSeconds: Number(process.env.KC_ACCESS_TOKEN_LIFESPAN_SECONDS || 30),
    tokenMinTtlSeconds: Number(process.env.KC_TOKEN_MIN_TTL_SECONDS || 20)
  };
}

// This harness is deliberately scoped to stg only (see README.md). Both
// provision.js and repro.js call this so a .env misconfiguration can't
// silently point real logins/session overrides at prod.
function assertStgTarget (env) {
  if (!/stg/i.test(env.kcBaseUrl)) {
    throw new Error(
      `KC_BASE_URL "${env.kcBaseUrl}" doesn't look like a staging URL (expected it to contain "stg").\n` +
      'This harness is scoped to stg only for now - refusing to continue.'
    );
  }
  // The internal admin hostname uses Smartling's "dev" naming convention for
  // what the team refers to as stg (confirmed against Slack history - e.g.
  // admin-keycloak-ha-v26.inception.dev.smartling.net was linked as "Stg KC
  // sessions settings"), so accept either "stg" or "dev" here rather than
  // just "stg" - but still hard-fail on anything that matches neither.
  if (env.kcAdminBaseUrl && !/(stg|dev)/i.test(env.kcAdminBaseUrl)) {
    throw new Error(
      `KC_ADMIN_BASE_URL "${env.kcAdminBaseUrl}" doesn't look like a stg/dev admin URL.\n` +
      'This harness is scoped to stg only for now - refusing to continue.'
    );
  }
}

module.exports = { requireEnv, assertStgTarget };
