#!/usr/bin/env node
'use strict';

// Creates (or tears down) a throwaway OIDC client + test user in the stg
// Smartling realm, scoped ONLY to this harness. Session/token overrides are
// applied to this one client's Advanced settings, not the realm-wide SSO
// Session Max, so nobody else's stg session is affected. See README.md
// "Known unknowns" - the exact attribute keys used here haven't been
// confirmed against a live KC26 admin console yet.
//
// SAFETY MODEL:
//   - Nothing is created/updated/deleted unless --apply is passed. Without
//     it, this only reads and prints what it WOULD do.
//   - Refuses to run against anything that doesn't look like a stg URL.
//   - Every client/user this tool creates carries a MARKER_KEY attribute.
//     Updating or deleting an EXISTING client/user is refused unless that
//     marker is already present, so a clientId/username collision with
//     something real can never be silently modified or deleted.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { requireEnv, assertStgTarget } = require('./lib/env');
const { createAdminClient } = require('./lib/admin-client');
const { promptLine } = require('./lib/prompt');

const ENV_PATH = path.join(__dirname, '.env');
const TEARDOWN = process.argv.includes('--teardown');
const APPLY = process.argv.includes('--apply');
const MARKER_KEY = 'smartling.playwright-repro';

function getTotpArg () {
  const arg = process.argv.find((a) => a.startsWith('--totp='));
  return arg ? arg.split('=')[1] : null;
}

// TOTP codes expire in ~30s, so they can never live in .env like the other
// credentials - they're supplied fresh per invocation, either via --totp on
// the command line (for non-interactive use), --no-totp to explicitly skip
// (for accounts with no MFA configured), or an interactive prompt.
async function resolveTotp () {
  if (process.argv.includes('--no-totp')) {
    return undefined;
  }
  const fromArg = getTotpArg();
  if (fromArg) {
    return fromArg;
  }
  const entered = await promptLine('TOTP code for KC_ADMIN_USERNAME (leave blank if this account has no MFA): ');
  return entered || undefined;
}

// Guarantees at least 2 of each character class (plain random base64url can
// easily miss uppercase entirely by chance, which is exactly what happened
// against the Smartling realm's password policy on the first attempt here).
function generatePassword () {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const digits = '23456789';
  const special = '!@#%^*-_=+';
  const all = upper + lower + digits + special;
  const pick = (charset) => charset[crypto.randomInt(charset.length)];

  const required = [
    pick(upper), pick(upper),
    pick(lower), pick(lower),
    pick(digits), pick(digits),
    pick(special), pick(special)
  ];
  const targetLength = 24;
  const rest = Array.from({ length: targetLength - required.length }, () => pick(all));
  const chars = [...required, ...rest];

  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// Writes a generated/fetched secret into the local .env so re-running
// provision.js (or running repro.js) picks it up without the operator having
// to copy/paste it by hand.
function persistEnvValue (key, value) {
  const contents = fs.readFileSync(ENV_PATH, 'utf8');
  const line = `${key}=${value}`;
  const pattern = new RegExp(`^${key}=.*$`, 'm');
  const updated = pattern.test(contents)
    ? contents.replace(pattern, line)
    : `${contents.trimEnd()}\n${line}\n`;
  fs.writeFileSync(ENV_PATH, updated);
}

function isOwnedByUs (representation) {
  const attrs = representation.attributes || {};
  const value = Array.isArray(attrs[MARKER_KEY]) ? attrs[MARKER_KEY][0] : attrs[MARKER_KEY];
  return value === 'true';
}

async function findClient (admin, env) {
  const matches = await admin.clients.find({ realm: env.kcRealm, clientId: env.kcClientId });
  return matches[0] || null;
}

async function findUser (admin, env) {
  const matches = await admin.users.find({ realm: env.kcRealm, username: env.kcTestUsername, exact: true });
  return matches[0] || null;
}

async function planOrTeardownClient (admin, env) {
  const existing = await findClient(admin, env);
  if (!existing) {
    console.log(`[client] "${env.kcClientId}" not found - nothing to delete.`);
    return;
  }

  if (!isOwnedByUs(existing)) {
    throw new Error(
      `[client] "${env.kcClientId}" (${existing.id}) exists but is missing the ${MARKER_KEY} marker ` +
      'this tool sets on everything it creates. Refusing to delete a client this tool did not create. ' +
      'Verify by hand in the admin console, or pick a different KC_CLIENT_ID.'
    );
  }

  if (!APPLY) {
    console.log(`[PLAN] Would delete client "${env.kcClientId}" (${existing.id}). Re-run with --apply to actually delete it.`);
    return;
  }

  await admin.clients.del({ id: existing.id, realm: env.kcRealm });
  console.log(`[APPLIED] Deleted client "${env.kcClientId}" (${existing.id}).`);
}

async function planOrTeardownUser (admin, env) {
  const existing = await findUser(admin, env);
  if (!existing) {
    console.log(`[user] "${env.kcTestUsername}" not found - nothing to delete.`);
    return;
  }

  if (!isOwnedByUs(existing)) {
    throw new Error(
      `[user] "${env.kcTestUsername}" (${existing.id}) exists but is missing the ${MARKER_KEY} marker ` +
      'this tool sets on everything it creates. Refusing to delete a user this tool did not create. ' +
      'Verify by hand in the admin console, or pick a different KC_TEST_USERNAME.'
    );
  }

  if (!APPLY) {
    console.log(`[PLAN] Would delete user "${env.kcTestUsername}" (${existing.id}). Re-run with --apply to actually delete it.`);
    return;
  }

  await admin.users.del({ id: existing.id, realm: env.kcRealm });
  console.log(`[APPLIED] Deleted user "${env.kcTestUsername}" (${existing.id}).`);
}

function buildClientRep (env) {
  const redirectUri = `http://localhost:${env.fixtureAppPort}/*`;
  const rootUrl = `http://localhost:${env.fixtureAppPort}`;

  // These are Keycloak's standard "Fine Grain OpenID Connect Configuration"
  // per-client attribute keys, shown in the admin console under
  // Clients -> <client> -> Advanced. Confirm they land there as expected -
  // see README.md "Known unknowns".
  const attributes = {
    'client.session.idle.timeout': String(env.clientSessionIdleSeconds),
    'client.session.max.lifespan': String(env.clientSessionMaxSeconds),
    'access.token.lifespan': String(env.accessTokenLifespanSeconds),
    [MARKER_KEY]: 'true'
  };

  return {
    clientId: env.kcClientId,
    enabled: true,
    // Confidential, not public: ensureFreshness()'s refresh_token request
    // (grant-manager.js) omits client_id from the POST body, relying on the
    // Authorization: Basic header postOptions() only adds for confidential
    // clients. A public client's refresh therefore fails with
    // "invalid_client" - confirmed live. Real production clients
    // (tms-dashboard-app etc.) are presumably confidential, which is why
    // this hasn't surfaced there. Matching that here is also more faithful
    // to production, not just a workaround.
    publicClient: false,
    protocol: 'openid-connect',
    rootUrl,
    redirectUris: [redirectUri],
    webOrigins: [rootUrl],
    attributes
  };
}

async function provisionClient (admin, env) {
  const clientRep = buildClientRep(env);
  const existing = await findClient(admin, env);

  if (existing && !isOwnedByUs(existing)) {
    throw new Error(
      `[client] "${env.kcClientId}" (${existing.id}) already exists but is missing the ${MARKER_KEY} marker ` +
      'this tool sets on everything it creates. Refusing to modify a client this tool did not create. ' +
      'Pick a different KC_CLIENT_ID, or verify by hand in the admin console first.'
    );
  }

  if (!APPLY) {
    console.log(`[PLAN] Would ${existing ? 'update' : 'create'} client "${env.kcClientId}" with:`);
    console.log(JSON.stringify(clientRep, null, 2));
    console.log('Re-run with --apply to actually make this change.');
    return;
  }

  let clientId;
  if (existing) {
    await admin.clients.update({ id: existing.id, realm: env.kcRealm }, clientRep);
    clientId = existing.id;
    console.log(`[APPLIED] Updated existing client "${env.kcClientId}" (${clientId}).`);
  } else {
    const created = await admin.clients.create({ ...clientRep, realm: env.kcRealm });
    clientId = created.id;
    console.log(`[APPLIED] Created client "${env.kcClientId}" (${clientId}).`);
  }

  // Read back what KC actually stored, rather than trusting the payload we
  // sent, so this can be eyeballed against the admin console.
  const stored = await admin.clients.findOne({ id: clientId, realm: env.kcRealm });
  console.log('Live attributes now stored on this client (cross-check against Clients -> Advanced in the admin console):');
  console.log(`  client.session.idle.timeout = ${stored.attributes['client.session.idle.timeout']}`);
  console.log(`  client.session.max.lifespan = ${stored.attributes['client.session.max.lifespan']}`);
  console.log(`  access.token.lifespan       = ${stored.attributes['access.token.lifespan']}`);

  const { value: secret } = await admin.clients.getClientSecret({ id: clientId, realm: env.kcRealm });
  persistEnvValue('KC_CLIENT_SECRET', secret);
  console.log('Client secret fetched and saved to .env as KC_CLIENT_SECRET (not printed here).');
}

async function provisionUser (admin, env) {
  const existing = await findUser(admin, env);

  if (existing && !isOwnedByUs(existing)) {
    throw new Error(
      `[user] "${env.kcTestUsername}" (${existing.id}) already exists but is missing the ${MARKER_KEY} marker ` +
      'this tool sets on everything it creates. Refusing to touch a user this tool did not create - ' +
      'resetting a real user\'s password would be exactly the kind of mistake these guardrails exist to prevent. ' +
      'Pick a different KC_TEST_USERNAME.'
    );
  }

  // Always (re)apply the password below, even if the user already exists -
  // an earlier run can create the user but fail on reset-password (e.g. a
  // generated password rejected by the realm's password policy, as happened
  // here), leaving an owned user with no usable credential. Re-running must
  // fix that, not silently treat "user exists" as "fully provisioned".
  if (!APPLY) {
    console.log(`[PLAN] Would ${existing ? 'ensure a password is set on' : 'create'} user "${env.kcTestUsername}" (enabled, password-only auth, marked with ${MARKER_KEY}).`);
    console.log('Re-run with --apply to actually do this.');
    return;
  }

  const password = env.kcTestPassword || generatePassword();
  let userId = existing && existing.id;

  if (existing) {
    console.log(`[user] "${env.kcTestUsername}" already exists (${userId}, owned by this tool) - ensuring password is set.`);
  } else {
    // Smartling's stg login theme's first step is an HTML type="email" field
    // with native browser validation - a non-email-shaped username can
    // never even be submitted, regardless of what Keycloak itself would
    // accept. Set email = username so what's typed in the browser matches
    // what Keycloak looks the user up by.
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(env.kcTestUsername)) {
      console.log(
        `WARNING: KC_TEST_USERNAME "${env.kcTestUsername}" isn't email-shaped. ` +
        'The stg login form requires an email-shaped value in its first field - login will fail. ' +
        'Use something like playwright-repro-test-user@stg-repro.invalid instead.'
      );
    }
    const created = await admin.users.create({
      realm: env.kcRealm,
      username: env.kcTestUsername,
      email: env.kcTestUsername,
      enabled: true,
      emailVerified: true,
      attributes: { [MARKER_KEY]: ['true'] }
    });
    userId = created.id;
    console.log(`[APPLIED] Created user "${env.kcTestUsername}" (${userId}).`);
  }

  try {
    await admin.users.resetPassword({
      id: userId,
      realm: env.kcRealm,
      credential: { type: 'password', value: password, temporary: false }
    });
    console.log(`[APPLIED] Password set for user "${env.kcTestUsername}" (${userId}).`);
  } catch (err) {
    // This specific rejection means the password we're "resetting" to is
    // already the current one (KC's password-history policy treats
    // resetting to the unchanged value as reuse) - not a real failure.
    const kcError = err.response && err.response.data && err.response.data.error;
    if (kcError === 'invalidPasswordHistoryMessage' && env.kcTestPassword) {
      console.log(`[user] Password for "${env.kcTestUsername}" is already set to the value in KC_TEST_PASSWORD - no change needed.`);
    } else {
      throw err;
    }
  }

  if (!env.kcTestPassword) {
    persistEnvValue('KC_TEST_PASSWORD', password);
    console.log(`Generated password and saved it to .env as KC_TEST_PASSWORD (only printed this once): ${password}`);
  }
}

async function main () {
  const env = requireEnv();
  assertStgTarget(env);

  console.log(`Target: ${env.kcBaseUrl} (OIDC)  /  ${env.kcAdminBaseUrl} (Admin API)  realm=${env.kcRealm}  client=${env.kcClientId}`);
  console.log(`Mode: ${APPLY ? 'APPLY (will make real changes)' : 'DRY RUN (no changes will be made - pass --apply to execute)'}`);
  console.log('');

  const totp = await resolveTotp();
  const admin = await createAdminClient(env, { totp });
  console.log('Admin auth succeeded. Looking up existing client/user (read-only)...');

  if (TEARDOWN) {
    await planOrTeardownClient(admin, env);
    await planOrTeardownUser(admin, env);
    return;
  }

  await provisionClient(admin, env);
  await provisionUser(admin, env);
}

main().catch((err) => {
  const detail = err.response && err.response.data
    ? `\nKeycloak response: ${JSON.stringify(err.response.data)}`
    : '';
  const requestInfo = err.config
    ? `\nRequest: ${err.config.method?.toUpperCase()} ${err.config.url}`
    : '';
  console.error(`provision.js failed: ${err.message || err}${requestInfo}${detail}`);
  process.exit(1);
});
