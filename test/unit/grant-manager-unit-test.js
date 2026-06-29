'use strict';

const test = require('tape');
const nock = require('nock');
const GrantManager = require('../../middleware/auth-utils/grant-manager');

const KC_HOST = 'http://localhost:8080';
const KC_TOKEN_PATH = '/auth/realms/test/protocol/openid-connect/token';

function makeManager (tokenMinTtl) {
  return new GrantManager({
    realmUrl: KC_HOST + '/auth/realms/test',
    clientId: 'test-client',
    public: true,
    tokenMinTtl: tokenMinTtl !== undefined ? tokenMinTtl : 90,
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
  mgr.createGrant = () => Promise.resolve(grant);
}

test('Fix2: capped token (exp-iat=88, tokenMinTtl=90) rejects with session-near-max error', t => {
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

test('Fix2: exp-iat=89 (one second inside threshold) rejects', t => {
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

test('Fix2: exp-iat=1 (extreme cap) rejects', t => {
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

test('Fix2: callback style - capped token calls callback with error', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-4' }), false);
  mgr.ensureFreshness(grant, (err) => {
    t.ok(err, 'error passed to callback');
    t.equal(err.message, 'Session near maximum lifespan: re-login required');
    t.end();
  });
});

test('Fix2: exp-iat=90 equals tokenMinTtl (boundary exclusive) - does not reject via Fix 2', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+80) - (n-10) = 90 = tokenMinTtl  →  NOT less than, should not reject via Fix 2
  const grant = withRtExpired(makeGrant({ atExp: n + 80, atIat: n - 10, rtJti: 'jti-5' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
    .catch(err => {
      if (err.message === 'Session near maximum lifespan: re-login required') {
        t.fail('Fix 2 should NOT reject for exp-iat=90 (not less than tokenMinTtl=90)');
      } else {
        t.pass('did not reject via Fix 2 (error: ' + err.message + ')');
      }
      t.end();
    });
});

test('Fix2: exp-iat=480 (normal token, tokenMinTtl=90) - does not reject via Fix 2', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // exp - iat = (n+470) - (n-10) = 480  >=  90
  const grant = withRtExpired(makeGrant({ atExp: n + 470, atIat: n - 10, rtJti: 'jti-6' }), false);
  setupPassThroughRefresh(mgr, grant);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('Fix2: already-expired token with capped lifetime (isExpired=true) does not trigger Fix 2', t => {
  const mgr = makeManager(90);
  const n = nowSec();
  // isExpired()=true because exp is in the past; Fix 2 guard checks !isExpired() first
  const grant = withRtExpired(makeGrant({ atExp: n - 10, atIat: n - 98, rtJti: 'jti-7' }), false);
  // exp - iat = 88 < 90, but isExpired() is true → Fix 2 skipped
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
    .catch(err => {
      if (err.message === 'Session near maximum lifespan: re-login required') {
        t.fail('Fix 2 should NOT reject because isExpired()=true');
      } else {
        t.pass('did not reject via Fix 2 (error: ' + err.message + ')');
      }
      t.end();
    });
});

test('Fix2: tokenMinTtl=0 - Fix 2 check skipped entirely', t => {
  // With tokenMinTtl=0: willTokenExpireBeforeTimeToLive(0) === isExpired().
  // A non-expired token returns fresh immediately via the first guard.
  const mgr = makeManager(0);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-8' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('returned early as fresh (Fix 2 never reached)'); t.end(); })
    .catch(err => { t.fail('unexpected rejection: ' + err.message); t.end(); });
});

test('Fix2: tokenMinTtl=undefined defaults to 90 - should trigger Fix 2 for capped token', t => {
  // makeManager(undefined) defaults to 90 per the makeManager function
  const mgr = makeManager(undefined);
  const n = nowSec();
  const grant = withRtExpired(makeGrant({ atExp: n + 86, atIat: n - 2, rtJti: 'jti-9' }), false);
  mgr.ensureFreshness(grant)
    .then(() => { t.fail('should have rejected'); t.end(); })
    .catch(err => {
      t.equal(err.message, 'Session near maximum lifespan: re-login required');
      t.end();
    });
});

test('Fix2: no access_token on grant - Fix 2 check skipped', t => {
  const mgr = makeManager(90);
  const grant = {
    access_token: undefined,
    refresh_token: { token: 'rt', content: { jti: 'jti-10' }, isExpired: () => false },
    isExpired: () => true,
    willTokenExpireBeforeTimeToLive: () => true
  };
  mgr.ensureFreshness(grant)
    .then(() => { t.pass('resolved without Fix 2 rejection'); t.end(); })
    .catch(err => {
      if (err.message === 'Session near maximum lifespan: re-login required') {
        t.fail('Fix 2 should NOT reject because access_token is undefined');
      } else {
        t.pass('did not reject via Fix 2 (error: ' + err.message + ')');
      }
      t.end();
    });
});
