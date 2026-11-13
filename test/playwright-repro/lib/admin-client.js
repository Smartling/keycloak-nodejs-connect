'use strict';

// Thin wrapper around @keycloak/keycloak-admin-client, following the same
// pattern as test/utils/realm.js in the main test suite (that one is hardcoded
// to a local 127.0.0.1:8080 dev Keycloak; this one targets stg via env config
// so it's portable across machines - see lib/env.js).
//
// The package is ESM-only, so this stays a plain async factory rather than a
// module-level promise, to keep call sites explicit about when auth happens.
async function createAdminClient (env, { totp } = {}) {
  const mod = await import('@keycloak/keycloak-admin-client');
  const KcAdminClient = mod.default;

  // Uses kcAdminBaseUrl (the internal hostname), NOT kcBaseUrl (the public
  // one) - confirmed by direct testing that the public hostname blocks every
  // /admin/* path at the network layer regardless of credentials or realm,
  // while the internal hostname serves the real Admin REST API.
  //
  // realmName belongs on the constructor's ConnectionConfig, not on the
  // Credentials object passed to .auth() (that type has no realmName field
  // at all - passing it there is silently ignored, and the token request
  // would otherwise default to realm "master").
  const client = new KcAdminClient({ baseUrl: env.kcAdminBaseUrl, realmName: env.kcAdminRealm });
  try {
    await client.auth({
      username: env.kcAdminUsername,
      password: env.kcAdminPassword,
      grantType: 'password',
      clientId: env.kcAdminClientId,
      ...(totp ? { totp } : {})
    });
  } catch (err) {
    // Surface Keycloak's actual token-endpoint error body (e.g.
    // {"error":"...","error_description":"..."}) instead of just the bare
    // HTTP status axios reports, since that's what actually explains a
    // 401/403 here.
    const detail = err.response && err.response.data
      ? `\nKeycloak response: ${JSON.stringify(err.response.data)}`
      : '';
    throw new Error(`Admin auth failed against ${env.kcAdminBaseUrl} (realm "${env.kcAdminRealm}"): ${err.message}${detail}`);
  }

  return client;
}

module.exports = { createAdminClient };
