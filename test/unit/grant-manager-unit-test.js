'use strict';

const test = require('tape');
const GrantManager = require('../../middleware/auth-utils/grant-manager');

const nock = require('nock');

const KC_HOST = 'http://localhost:8080';
const KC_TOKEN_PATH = '/auth/realms/test/protocol/openid-connect/token';

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
// rtExpired controls whether refresh_token.isExpired() returns true.
function makeGrant ({ atExp, atIat, rtJti, rtExpired = false }) {
  return {
    access_token: atExp !== undefined ? {
      content: { exp: atExp, iat: atIat }
    } : undefined,
    refresh_token: {
      token: 'fake-refresh-token',
      content: rtJti ? { jti: rtJti } : {}
    },
    isExpired: function () {
      if (!this.access_token) return true;
      return (atExp * 1000) < Date.now();
    },
    willTokenExpireBeforeTimeToLive: function (ttl) {
      if (!this.access_token) return true;
      return (atExp - ttl) * 1000 < Date.now();
    },
    // refresh_token.isExpired is a separate function
    _rtExpired: rtExpired
  };
}

// Patch refresh_token.isExpired onto grants created by makeGrant
function withRtExpired (grant, expired) {
  grant.refresh_token.isExpired = () => expired;
  return grant;
}

// ─── Fix 2: Session-cap detection ────────────────────────────────────────────

// Helper: mock createGrant to avoid HTTP calls and JWT validation.
// This allows ensureFreshness to proceed past Fix 2 without hitting network issues.
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
      t.equal(err.message, 'Session near maximum lifespan: re-login required');
      t.end();
    });
});

test('session-capped token via callback style delivers error to callback', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-4' }), false);
  mgr.ensureFreshness(grant, (err) => {
    t.ok(err, 'error passed to callback');
    t.equal(err.message, 'Session near maximum lifespan: re-login required');
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
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('token with normal 480s issued lifetime proceeds to normal refresh', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+470) - (n-10) = 480  >=  90
  const grant = withRtExpired(makeGrant({ atExp: n + 470, atIat: n - 10, rtJti: 'jti-6' }), false);
  setupPassThroughRefresh(mgr, grant);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
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
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('min-ttl of zero disables session-cap detection', t => {
  // With tokenMinTtl=0: willTokenExpireBeforeTimeToLive(0) === isExpired().
  // A non-expired token returns fresh immediately via the first guard.
  const mgr = makeManager(0);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-8' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('returned early as fresh (Fix 2 never reached)'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('undefined min-ttl disables session-cap detection', t => {
  const mgr = makeManager(undefined);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-9' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('returned early as fresh (Fix 2 never reached)'); t.end(); })
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
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

// ─── Fix 1: Refresh deduplication ────────────────────────────────────────────

// Helper: grant needing refresh (capped token but with tokenMinTtl=0 so Fix 2 skips it),
// with a jti so dedup applies.
function makeRefreshNeededGrant (jti) {
  const n = nowSec();
  // expired token → ensureFreshness proceeds to fetch
  const g = withRtExpired(makeGrant({ atExp: n - 10, atIat: n - 98, rtJti: jti }), false);
  return g;
}

// Sets up a single nock interceptor and mocks createGrant.
// Returns the manager so callers can also inspect _pendingRefreshes.
function setupFix1Manager () {
  const mgr = makeManager(0); // tokenMinTtl=0 so Fix 2 is never triggered
  mgr.createGrant = () => Promise.resolve(makeRefreshNeededGrant('jti-new'));
  return mgr;
}

test('two concurrent refreshes for the same token share one Keycloak request', t => {
  nock.cleanAll();
  const mgr = setupFix1Manager();
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
  const mgr = setupFix1Manager();
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
  const mgr = setupFix1Manager();
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
  const mgr = setupFix1Manager();
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
  const mgr = setupFix1Manager();
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
  const mgr = setupFix1Manager();
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
  const mgr = setupFix1Manager();
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
  const mgr = setupFix1Manager();
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

