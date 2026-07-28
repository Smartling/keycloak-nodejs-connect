'use strict';

const test = require('tape');
const GrantManager = require('../../middleware/auth-utils/grant-manager');
const { SessionExpiredError } = require('../../middleware/auth-utils/errors');

const nock = require('nock');

const KC_HOST = 'http://localhost:8080';
const KC_TOKEN_PATH = '/auth/realms/test/protocol/openid-connect/token';
const KC_LOGOUT_PATH = '/auth/realms/test/protocol/openid-connect/logout';

function makeManager (tokenMinTtl) {
  return new GrantManager({
    realmUrl: KC_HOST + '/auth/realms/test',
    clientId: 'test-client',
    public: true,
    tokenMinTtl: tokenMinTtl,
    minTimeBetweenJwksRequests: 0
  });
}

function nowSec () {
  return Math.floor(Date.now() / 1000);
}

// Builds a plain-object grant with the right interface for ensureFreshness.
// atExp/atIat in seconds-since-epoch. rtJti is the refresh token jti (string or null).
// rtExpired controls whether refresh_token.isExpired() returns true (default false).
function makeGrant ({ atExp, atIat, rtJti, rtExpired = false }) {
  return {
    access_token: atExp !== undefined ? {
      content: { exp: atExp, iat: atIat }
    } : undefined,
    refresh_token: {
      token: 'fake-refresh-token',
      content: rtJti ? { jti: rtJti } : {},
      isExpired: () => rtExpired
    },
    isExpired: function () {
      if (!this.access_token) return true;
      return (atExp * 1000) < Date.now();
    },
    willTokenExpireBeforeTimeToLive: function (ttl) {
      if (!this.access_token) return true;
      return (atExp - ttl) * 1000 < Date.now();
    }
  };
}

// Patch refresh_token.isExpired onto grants created by makeGrant
function withRtExpired (grant, expired) {
  grant.refresh_token.isExpired = () => expired;
  return grant;
}

// ─── Session-cap detection ───────────────────────────────────────────────────

// Helper: mock createGrant to avoid HTTP calls and JWT validation.
// This allows ensureFreshness to proceed past the session-cap guard without hitting the network.
function setupPassThroughRefresh (mgr, grant) {
  nock.cleanAll();
  nock(KC_HOST)
    .post(KC_TOKEN_PATH)
    .once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));
  mgr.createGrant = () => Promise.resolve(grant);
}

test('session-capped token (exp-iat=88, min-ttl=90) triggers re-login rejection', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+86) - (n-2) = 88  <  tokenMinTtl=90  →  should reject
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-1' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.fail('should have rejected'); t.end(); })
    .catch(err => {
      t.ok(err instanceof SessionExpiredError, 'error is a SessionExpiredError');
      t.equal(err.message, 'Session near maximum lifespan: re-login required');
      t.end();
    });
});

test('session-capped token one second inside min-ttl threshold triggers re-login rejection', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+80) - (n-9) = 89  <  90
  const grant = withRtExpired(makeGrant({ atExp: n + 80, atIat: n - 9, rtJti: 'jti-2' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.fail('should have rejected'); t.end(); })
    .catch(err => {
      t.ok(err instanceof SessionExpiredError, 'error is a SessionExpiredError');
      t.equal(err.message, 'Session near maximum lifespan: re-login required');
      t.end();
    });
});

test('session-capped token with 1s issued lifetime triggers re-login rejection', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+50) - (n+49) = 1  <  90
  const grant = withRtExpired(makeGrant({ atExp: n + 50, atIat: n + 49, rtJti: 'jti-3' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.fail('should have rejected'); t.end(); })
    .catch(err => {
      t.ok(err instanceof SessionExpiredError, 'error is a SessionExpiredError');
      t.equal(err.message, 'Session near maximum lifespan: re-login required');
      t.end();
    });
});

test('session-capped token via callback style delivers error to callback', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-4' }), false);
  nock(KC_HOST).post(KC_LOGOUT_PATH).once().reply(204);
  mgr.ensureFreshness(grant, (err) => {
    t.ok(err, 'error passed to callback');
    t.ok(err instanceof SessionExpiredError, 'error is a SessionExpiredError');
    t.equal(err.message, 'Session near maximum lifespan: re-login required');
    t.end();
  });
});

test('session-capped token carries grant and idTokenHint from grant id_token', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-hint' }), false);
  grant.id_token = { token: 'id.token.value' };
  mgr.ensureFreshness(grant)
    .then(() => { t.fail('should have rejected'); t.end(); })
    .catch(err => {
      t.ok(err instanceof SessionExpiredError, 'error is a SessionExpiredError');
      t.equal(err.grant, grant, 'error carries the grant object');
      t.equal(err.idTokenHint, 'id.token.value', 'idTokenHint is derived from grant.id_token.token');
      t.end();
    });
});

test('session-capped token has undefined idTokenHint when grant has no id_token', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-nohint' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.fail('should have rejected'); t.end(); })
    .catch(err => {
      t.ok(err instanceof SessionExpiredError, 'error is a SessionExpiredError');
      t.equal(err.grant, grant, 'error carries the grant object');
      t.equal(err.idTokenHint, undefined, 'idTokenHint is undefined when no id_token present');
      t.end();
    });
});

test('token with issued lifetime equal to min-ttl boundary is not treated as capped', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+80) - (n-10) = 90 = tokenMinTtl  →  NOT less than, should not reject via Fix 2
  const grant = withRtExpired(makeGrant({ atExp: n + 80, atIat: n - 10, rtJti: 'jti-5' }), false);
  setupPassThroughRefresh(mgr, grant);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without session-cap rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('token with normal 480s issued lifetime proceeds to normal refresh', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+470) - (n-10) = 480  >=  90
  const grant = withRtExpired(makeGrant({ atExp: n + 470, atIat: n - 10, rtJti: 'jti-6' }), false);
  setupPassThroughRefresh(mgr, grant);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without session-cap rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('expired token with short issued lifetime falls through to normal refresh path', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // isExpired()=true because exp is in the past; Fix 2 guard checks !isExpired() first
  const grant = withRtExpired(makeGrant({ atExp: n - 10, atIat: n - 98, rtJti: 'jti-7' }), false);
  // exp - iat = 88 < 90, but isExpired() is true → Fix 2 skipped
  setupPassThroughRefresh(mgr, grant);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without session-cap rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('min-ttl of zero disables session-cap detection', t => {
  // With tokenMinTtl=0: willTokenExpireBeforeTimeToLive(0) === isExpired().
  // A non-expired token returns fresh immediately via the first guard.
  const mgr = makeManager(0);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-8' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('returned early as fresh (session-cap guard never reached)'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('undefined min-ttl disables session-cap detection', t => {
  const mgr = makeManager(undefined);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-9' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('returned early as fresh (session-cap guard never reached)'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('grant without access token skips session-cap detection', t => {
  const mgr = makeManager(90);
  const grant = {
    access_token: undefined,
    refresh_token: { token: 'rt', content: { jti: 'jti-10' }, isExpired: () => false },
    isExpired: () => true,
    willTokenExpireBeforeTimeToLive: () => true
  };
  setupPassThroughRefresh(mgr, grant);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without session-cap rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

// ─── Concurrent refresh deduplication ───────────────────────────────────────

// Helper: expired grant with a jti so deduplication applies.
// tokenMinTtl=0 disables session-cap detection, keeping these tests focused on dedup only.
function makeRefreshNeededGrant (jti) {
  const n = nowSec();
  const g = withRtExpired(makeGrant({ atExp: n - 10, atIat: n - 98, rtJti: jti }), false);
  return g;
}

// Sets up a manager with session-cap detection disabled (tokenMinTtl=0) and mocks createGrant.
function setupDedupManager () {
  const mgr = makeManager(0);
  mgr.createGrant = () => Promise.resolve(makeRefreshNeededGrant('jti-new'));
  return mgr;
}

test('two concurrent refreshes for the same token share one Keycloak request', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  const grant = makeRefreshNeededGrant('jti-dedup-2');
  mgr.createGrant = () => Promise.resolve(grant);

  // Exactly one interceptor - if two fetches are made, the second fails
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  const p1 = mgr.ensureFreshness(grant);
  const p2 = mgr.ensureFreshness(grant);

  Promise.all([p1, p2])
    .then(() => { t.pass('both concurrent calls resolved via single fetch'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('three concurrent refreshes for the same token share one Keycloak request', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  const grant = makeRefreshNeededGrant('jti-dedup-3');
  mgr.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  const p1 = mgr.ensureFreshness(grant);
  const p2 = mgr.ensureFreshness(grant);
  const p3 = mgr.ensureFreshness(grant);

  Promise.all([p1, p2, p3])
    .then(() => { t.pass('all three concurrent calls resolved via single fetch'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('concurrent refreshes all receive the same error when Keycloak rejects', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  const grant = makeRefreshNeededGrant('jti-dedup-err');
  mgr.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(401, 'Unauthorized');

  const p1 = mgr.ensureFreshness(grant);
  const p2 = mgr.ensureFreshness(grant);

  Promise.all([
    p1.catch(e => e),
    p2.catch(e => e)
  ]).then(([err1, err2]) => {
    t.ok(err1 instanceof Error, 'p1 rejected with an Error');
    t.ok(err2 instanceof Error, 'p2 rejected with an Error');
    t.equal(err1, err2, 'both callers received the identical error object (same promise)');
    t.end();
  });
});

test('after successful refresh the deduplication map is cleared for future requests', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  const grant = makeRefreshNeededGrant('jti-dedup-reuse');
  mgr.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  mgr.ensureFreshness(grant)
    .then(() => {
      t.equal(mgr._pendingRefreshes.size, 0, 'map is empty after first refresh settled');

      // Second call: needs a fresh interceptor since map was cleaned
      nock(KC_HOST).post(KC_TOKEN_PATH).once()
        .reply(200, JSON.stringify({ access_token: 'new2', refresh_token: 'new-rt2' }));

      return mgr.ensureFreshness(grant);
    })
    .then(() => { t.pass('second call after success issued a fresh fetch'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('after failed refresh the deduplication map is cleared for future requests', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  const grant = makeRefreshNeededGrant('jti-dedup-fail-retry');
  mgr.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(401, 'Unauthorized');

  mgr.ensureFreshness(grant)
    .catch(() => {
      t.equal(mgr._pendingRefreshes.size, 0, 'map is empty after failed refresh settled');

      nock(KC_HOST).post(KC_TOKEN_PATH).once()
        .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

      return mgr.ensureFreshness(grant);
    })
    .then(() => { t.pass('second call after failure issued a fresh fetch'); t.end(); })
    .catch(err => { t.fail('unexpected second failure: ' + err.message); t.end(); });
});

test('concurrent refreshes for different tokens each issue separate Keycloak requests', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  const grantA = makeRefreshNeededGrant('jti-A');
  const grantB = makeRefreshNeededGrant('jti-B');
  mgr.createGrant = () => Promise.resolve(grantA);

  // Two interceptors needed - one per distinct jti
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new-A', refresh_token: 'new-rt-A' }));
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new-B', refresh_token: 'new-rt-B' }));

  const p1 = mgr.ensureFreshness(grantA);
  const p2 = mgr.ensureFreshness(grantB);

  Promise.all([p1, p2])
    .then(() => { t.pass('both calls with different jtis completed independently'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('refresh tokens without jti claim bypass deduplication', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  // rtJti: null → no jti in refresh token content → dedup skipped
  const grant = withRtExpired(makeGrant({ atExp: nowSec() - 10, atIat: nowSec() - 98, rtJti: null }), false);
  mgr.createGrant = () => Promise.resolve(grant);

  // Two interceptors needed - no dedup means two fetches
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new1', refresh_token: 'new-rt1' }));
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new2', refresh_token: 'new-rt2' }));

  const p1 = mgr.ensureFreshness(grant);
  const p2 = mgr.ensureFreshness(grant);

  Promise.all([p1, p2])
    .then(() => { t.pass('both calls without jti completed with separate fetches'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('deduplication map is empty after all concurrent refreshes settle', t => {
  nock.cleanAll();
  const mgr = setupDedupManager();
  const grant = makeRefreshNeededGrant('jti-map-check');
  mgr.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  const p1 = mgr.ensureFreshness(grant);
  const p2 = mgr.ensureFreshness(grant);
  const p3 = mgr.ensureFreshness(grant);

  t.equal(mgr._pendingRefreshes.size, 1, 'map has one entry while request is in-flight');

  Promise.all([p1, p2, p3])
    .then(() => {
      t.equal(mgr._pendingRefreshes.size, 0, 'map is empty after all calls settle');
      t.end();
    })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

// ─── Cross-instance refresh coordination ────────────────────────────────────
//
// _pendingRefreshes only dedupes within a single process. When multiple app
// instances share one Keycloak session (e.g. two browser tabs routed to
// different instances by the load balancer), a configured `refreshCoordinator`
// lets one instance's in-flight refresh be shared with the others instead of
// each independently racing Keycloak.

// Fake shared coordinator simulating a Redis-backed claim/publish/await store. Tracks the
// per-key ownership token so a wiring bug (e.g. _coordinated forgetting to pass the token
// through to publish()) shows up as a dropped publish instead of passing silently.
function makeFakeCoordinator () {
  const locks = new Map(); // key -> token
  const results = new Map();
  let tokenCounter = 0;
  return {
    claim (key) {
      if (locks.has(key)) return Promise.resolve(null);
      const token = 'token-' + (++tokenCounter);
      locks.set(key, token);
      return Promise.resolve(token);
    },
    publish (key, value, ttlMs, token) {
      if (locks.get(key) !== token) return Promise.resolve();
      results.set(key, value);
      locks.delete(key);
      return Promise.resolve();
    },
    await (key, timeoutMs) {
      const start = Date.now();
      const poll = (resolve) => {
        if (results.has(key)) return resolve(results.get(key));
        if (Date.now() - start >= timeoutMs) return resolve(null);
        setTimeout(() => poll(resolve), 5);
      };
      return new Promise(poll);
    }
  };
}

// A coordinator whose claim always succeeds (nothing else ever holds the lock)
// but whose await() always times out - simulates a leader that claimed the
// lock and then crashed before publishing a result.
function makeStuckCoordinator () {
  return {
    claim () { return Promise.resolve('token-stuck'); },
    publish () { return Promise.resolve(); },
    await (key, timeoutMs) {
      return new Promise(resolve => setTimeout(() => resolve(null), Math.min(timeoutMs, 20)));
    }
  };
}

// A coordinator whose claim() always rejects (e.g. Redis unreachable) - simulates
// the coordinator itself being down before any claim attempt succeeds or fails
// cleanly. _coordinated should fall back to doFetch() rather than fail the caller.
function makeCoordinatorWithFailingClaim () {
  return {
    claim () { return Promise.reject(new Error('redis unavailable')); },
    publish () { return Promise.resolve(); },
    await () { return Promise.reject(new Error('redis unavailable')); }
  };
}

// A coordinator whose claim() always resolves null (never the leader) but whose
// await() rejects (e.g. Redis becomes unreachable partway through the wait).
// _coordinated should fall back to doFetch() rather than fail the caller.
function makeCoordinatorWithFailingAwait () {
  return {
    claim () { return Promise.resolve(null); },
    publish () { return Promise.resolve(); },
    await () { return Promise.reject(new Error('redis unavailable')); }
  };
}

function makeManagerWithCoordinator (tokenMinTtl, coordinator) {
  return new GrantManager({
    realmUrl: KC_HOST + '/auth/realms/test',
    clientId: 'test-client',
    public: true,
    tokenMinTtl: tokenMinTtl,
    minTimeBetweenJwksRequests: 0,
    refreshCoordinator: coordinator
  });
}

test('two separate GrantManager instances sharing a coordinator dedupe a concurrent refresh to one Keycloak call', t => {
  nock.cleanAll();
  const coordinator = makeFakeCoordinator();
  const grant = makeRefreshNeededGrant('jti-cross-instance');

  const mgr1 = makeManagerWithCoordinator(0, coordinator);
  const mgr2 = makeManagerWithCoordinator(0, coordinator);
  mgr1.createGrant = () => Promise.resolve(grant);
  mgr2.createGrant = () => Promise.resolve(grant);

  // Exactly one interceptor - if both instances independently call Keycloak, this fails.
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  const p1 = mgr1.ensureFreshness(grant);
  const p2 = mgr2.ensureFreshness(grant);

  Promise.all([p1, p2])
    .then(() => { t.pass('both instances resolved via a single Keycloak call'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('follower instance receives the leader\'s error via the coordinator instead of calling Keycloak itself', t => {
  nock.cleanAll();
  const coordinator = makeFakeCoordinator();
  const grant = makeRefreshNeededGrant('jti-cross-instance-err');

  const mgr1 = makeManagerWithCoordinator(0, coordinator);
  const mgr2 = makeManagerWithCoordinator(0, coordinator);
  mgr1.createGrant = () => Promise.resolve(grant);
  mgr2.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(401, 'Unauthorized');

  const p1 = mgr1.ensureFreshness(grant);
  const p2 = mgr2.ensureFreshness(grant);

  Promise.all([p1.catch(e => e), p2.catch(e => e)])
    .then(([e1, e2]) => {
      t.ok(e1 instanceof Error, 'leader rejected with an Error');
      t.ok(e2 instanceof Error, 'follower rejected with an Error');
      t.ok(e2.message.includes('401'), 'follower error carries the leader\'s failure details');
      t.equal(nock.pendingMocks().length, 0, 'exactly one KC call made across both instances');
      t.end();
    });
});

test('follower falls back to its own Keycloak call when the coordinator never publishes a result (leader crashed)', t => {
  nock.cleanAll();
  const coordinator = makeStuckCoordinator();
  const grant = makeRefreshNeededGrant('jti-cross-instance-timeout');

  const mgr2 = makeManagerWithCoordinator(0, coordinator);
  mgr2.createGrant = () => Promise.resolve(grant);

  // No leader ever actually calls Keycloak in this test scenario - only the
  // follower's self-heal fetch (after the coordinator wait times out) should fire.
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  mgr2.ensureFreshness(grant)
    .then(() => {
      t.equal(nock.pendingMocks().length, 0, 'follower made its own Keycloak call after coordinator wait timed out');
      t.end();
    })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

// A coordinator that models real Redis TTL expiry: an entry (lock sentinel or published
// result) simply disappears once its expiresAt passes, exactly like a Redis key with PX.
// Used to reproduce the race from https://github.com/Smartling/smartling-express/pull/59
// #discussion_r3664941181: if two followers both see await()=null when a leader's lock
// expires mid-wait, and _coordinated just fell back to doFetch() directly instead of
// re-claiming first, both followers would independently hit Keycloak.
function makeExpiringLockCoordinator () {
  const store = new Map(); // key -> { value, expiresAt }
  const read = (key) => {
    const entry = store.get(key);
    if (!entry) return undefined;
    if (Date.now() >= entry.expiresAt) {
      store.delete(key);
      return undefined;
    }
    return entry;
  };
  return {
    claim (key, ttlMs) {
      if (read(key)) return Promise.resolve(null);
      const token = 'token-' + Math.random().toString(36).slice(2);
      store.set(key, { value: 'sentinel:' + token, expiresAt: Date.now() + ttlMs });
      return Promise.resolve(token);
    },
    publish (key, value, ttlMs, token) {
      const entry = read(key);
      if (!entry || entry.value !== 'sentinel:' + token) return Promise.resolve();
      store.set(key, { value: JSON.stringify(value), expiresAt: Date.now() + ttlMs });
      return Promise.resolve();
    },
    await (key, timeoutMs) {
      const start = Date.now();
      const poll = (resolve) => {
        const entry = read(key);
        if (!entry) return resolve(null);
        if (!entry.value.startsWith('sentinel:')) return resolve(JSON.parse(entry.value));
        if (Date.now() - start >= timeoutMs) return resolve(null);
        setTimeout(() => poll(resolve), 5);
      };
      return new Promise(poll);
    }
  };
}

test('two followers re-claim instead of both independently calling Keycloak when the leader\'s lock expires mid-wait', t => {
  nock.cleanAll();
  const coordinator = makeExpiringLockCoordinator();
  const grant = makeRefreshNeededGrant('jti-reclaim-race');
  const key = 'kc-refresh:jti-reclaim-race';

  // A third, already-in-flight leader that's about to disappear (crashed/slow) - a
  // short-lived sentinel unrelated to either follower's own claim attempt below.
  coordinator.claim(key, 30);

  const mgr1 = makeManagerWithCoordinator(0, coordinator);
  const mgr2 = makeManagerWithCoordinator(0, coordinator);
  mgr1.createGrant = () => Promise.resolve(grant);
  mgr2.createGrant = () => Promise.resolve(grant);

  // Exactly one interceptor - if both followers see await()=null and immediately fall back
  // to doFetch() without re-claiming (the pre-fix behavior), the second real call has no
  // matching interceptor left and that follower's promise rejects.
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  const p1 = mgr1.ensureFreshness(grant);
  const p2 = mgr2.ensureFreshness(grant);

  Promise.all([p1, p2])
    .then(() => {
      t.equal(nock.pendingMocks().length, 0, 'exactly one Keycloak call across both followers');
      t.end();
    })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('falls back to its own Keycloak call when the coordinator\'s claim() rejects (coordinator unavailable)', t => {
  nock.cleanAll();
  const coordinator = makeCoordinatorWithFailingClaim();
  const grant = makeRefreshNeededGrant('jti-coordinator-claim-down');

  const mgr = makeManagerWithCoordinator(0, coordinator);
  mgr.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  mgr.ensureFreshness(grant)
    .then(() => {
      t.equal(nock.pendingMocks().length, 0, 'made its own Keycloak call despite claim() rejecting');
      t.end();
    })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('falls back to its own Keycloak call when the coordinator\'s await() rejects (coordinator unavailable)', t => {
  nock.cleanAll();
  const coordinator = makeCoordinatorWithFailingAwait();
  const grant = makeRefreshNeededGrant('jti-coordinator-await-down');

  const mgr = makeManagerWithCoordinator(0, coordinator);
  mgr.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  mgr.ensureFreshness(grant)
    .then(() => {
      t.equal(nock.pendingMocks().length, 0, 'made its own Keycloak call despite await() rejecting');
      t.end();
    })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('without a configured coordinator, two separate GrantManager instances do not dedupe (existing per-process-only behavior)', t => {
  nock.cleanAll();
  const grant = makeRefreshNeededGrant('jti-no-coordinator');

  const mgr1 = makeManager(0);
  const mgr2 = makeManager(0);
  mgr1.createGrant = () => Promise.resolve(grant);
  mgr2.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new1', refresh_token: 'new-rt1' }));
  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new2', refresh_token: 'new-rt2' }));

  Promise.all([mgr1.ensureFreshness(grant), mgr2.ensureFreshness(grant)])
    .then(() => { t.pass('each instance independently called Keycloak (no cross-instance coordination configured)'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

// ─── Cross-instance code-exchange coordination ──────────────────────────────
//
// Same coordinator primitive applied to obtainFromCode, keyed by the
// authorization code, so a duplicate/racing callback request (e.g. the
// original "Code already used for userSession" scenario) shares one Keycloak
// exchange across instances instead of each independently redeeming the code.

test('two separate GrantManager instances sharing a coordinator dedupe a concurrent code exchange to one Keycloak call', t => {
  nock.cleanAll();
  const coordinator = makeFakeCoordinator();
  const grant = { access_token: {}, refresh_token: undefined };

  const mgr1 = makeManagerWithCoordinator(0, coordinator);
  const mgr2 = makeManagerWithCoordinator(0, coordinator);
  mgr1.createGrant = () => Promise.resolve(grant);
  mgr2.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(200, JSON.stringify({ access_token: 'new', refresh_token: 'new-rt' }));

  const fakeRequest = { session: { id: 'sess-1' } };

  const p1 = mgr1.obtainFromCode(fakeRequest, 'dup-code', 'sess-1', undefined, 'http://app/callback');
  const p2 = mgr2.obtainFromCode(fakeRequest, 'dup-code', 'sess-1', undefined, 'http://app/callback');

  Promise.all([p1, p2])
    .then(() => { t.pass('both instances resolved via a single Keycloak code-exchange call'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('follower receives the leader\'s error for a duplicate code exchange instead of redeeming it again', t => {
  nock.cleanAll();
  const coordinator = makeFakeCoordinator();
  const grant = { access_token: {}, refresh_token: undefined };

  const mgr1 = makeManagerWithCoordinator(0, coordinator);
  const mgr2 = makeManagerWithCoordinator(0, coordinator);
  mgr1.createGrant = () => Promise.resolve(grant);
  mgr2.createGrant = () => Promise.resolve(grant);

  nock(KC_HOST).post(KC_TOKEN_PATH).once()
    .reply(400, 'Code already used for userSession');

  const fakeRequest = { session: { id: 'sess-1' } };

  const p1 = mgr1.obtainFromCode(fakeRequest, 'dup-code-2', 'sess-1', undefined, 'http://app/callback');
  const p2 = mgr2.obtainFromCode(fakeRequest, 'dup-code-2', 'sess-1', undefined, 'http://app/callback');

  Promise.all([p1.catch(e => e), p2.catch(e => e)])
    .then(([e1, e2]) => {
      t.ok(e1 instanceof Error, 'leader rejected with an Error');
      t.ok(e2 instanceof Error, 'follower rejected with an Error');
      t.equal(nock.pendingMocks().length, 0, 'exactly one KC call made across both instances - code redeemed only once');
      t.end();
    });
});

// ─── Integration: session-cap guard fires inside createGrant (storm path) ────
//
// When KC26 returns a new token with a shorter-than-configured lifetime (exp-iat < tokenMinTtl),
// the session-cap guard fires inside createGrant → all concurrent callers share the same
// rejected promise via deduplication and are redirected to login.

// Encode a plain object as base64url so Token can parse it.
function b64url (obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// Minimal parseable JWT. Signature is not validated: the session-cap guard fires before validateGrant.
function fakeJWT (payload) {
  return `${b64url({ alg: 'HS512', typ: 'JWT' })}.${b64url(payload)}.fakesig`;
}

test('session-cap guard fires inside createGrant when KC returns a capped token, rejecting all concurrent callers', t => {
  nock.cleanAll();

  const mgr = makeManager(90);
  const now = Math.floor(Date.now() / 1000);

  // Session grant: 480s-configured-lifetime token, 88s remaining.
  // willTokenExpireBeforeTimeToLive(90)=true → passes freshness guard, proceeds to KC refresh call.
  // exp-iat=480 >= tokenMinTtl=90 → session-cap guard does NOT fire on this grant.
  const sessionGrant = withRtExpired(makeGrant({
    atExp: now + 88,
    atIat: now + 88 - 480,
    rtJti: 'jti-storm'
  }), false);

  // KC responds with a capped 88s token (exp-iat=88 < tokenMinTtl=90).
  // refreshHandler calls createGrant(json) → createGrant calls ensureFreshness(newGrant)
  // → session-cap guard fires on newGrant → refreshPromise rejects → all concurrent callers rejected.
  nock(KC_HOST)
    .post(KC_TOKEN_PATH)
    .once()
    .reply(200, JSON.stringify({
      access_token: fakeJWT({ exp: now + 88, iat: now }),
      refresh_token: fakeJWT({ exp: now + 3600, iat: now, jti: 'rt-new' }),
      token_type: 'bearer',
      expires_in: 88
    }));

  const p1 = mgr.ensureFreshness(sessionGrant);
  const p2 = mgr.ensureFreshness(sessionGrant);
  const p3 = mgr.ensureFreshness(sessionGrant);

  t.equal(mgr._pendingRefreshes.size, 1, 'dedup: one in-flight KC call for the session');

  Promise.all([p1.catch(e => e), p2.catch(e => e), p3.catch(e => e)])
    .then(([e1, e2, e3]) => {
      t.ok(e1 instanceof SessionExpiredError, 'all callers rejected with SessionExpiredError');
      t.equal(e1.message, 'Session near maximum lifespan: re-login required',
        'session-cap error message propagates through refreshPromise to all callers');
      t.equal(e1, e2, 'p2 shares same rejection object as p1 (dedup)');
      t.equal(e1, e3, 'p3 shares same rejection object as p1 (dedup)');
      t.equal(mgr._pendingRefreshes.size, 0, 'map cleared after rejection');
      t.equal(nock.pendingMocks().length, 0, 'exactly one KC token call made');
      t.end();
    });
});

// ─── logout ─────────────────────────────────────────────────────────────────

test('logout: POSTs refresh_token to KC logout endpoint and resolves', t => {
  const mgr = makeManager();
  nock.cleanAll();
  nock(KC_HOST)
    .post(KC_LOGOUT_PATH, (body) => body.refresh_token === 'fake-refresh-token')
    .once()
    .reply(204, '');

  const grant = makeGrant({ atExp: nowSec() + 60, atIat: nowSec(), rtJti: 'jti-1' });
  mgr.logout(grant)
    .then(() => {
      t.equal(nock.pendingMocks().length, 0, 'exactly one POST to KC logout endpoint');
      t.end();
    })
    .catch(err => { t.fail('logout rejected: ' + err.message); t.end(); });
});

test('logout: rejects when KC returns an error status', t => {
  const mgr = makeManager();
  nock.cleanAll();
  nock(KC_HOST)
    .post(KC_LOGOUT_PATH)
    .once()
    .reply(400, 'Bad Request');

  const grant = makeGrant({ atExp: nowSec() + 60, atIat: nowSec(), rtJti: 'jti-1' });
  mgr.logout(grant)
    .then(() => { t.fail('should have rejected'); t.end(); })
    .catch(err => {
      t.ok(err.message.includes('400'), 'error contains status code');
      t.end();
    });
});

