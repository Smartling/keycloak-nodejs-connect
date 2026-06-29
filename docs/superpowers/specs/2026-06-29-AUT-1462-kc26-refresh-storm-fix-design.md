# AUT-1462 KC26 Refresh Token Storm - Fix Design

## Problem

After the Keycloak 1.9 to KC26 migration, users approaching the end of a 12-hour SSO session
trigger a burst of `REFRESH_TOKEN` requests from ti-next to Keycloak - starting at ~160 req/s
and escalating to ~1200 req/s for a single user session, lasting up to 2 minutes.

Two root causes work together to produce the storm:

1. **Session-cap trigger.** KC26 caps every access token's TTL at `min(accessTokenLifespan, remaining session time)`.
   In the last ~90s before session expiry, KC issues tokens with lifetimes of 88s, 29s, 1s... The adapter is
   configured with `token-minimum-time-to-live: 90`, so a freshly-minted 88s token is already inside the
   pre-refresh window the instant it is issued. Every subsequent HTTP request triggers `ensureFreshness`,
   which calls KC for another refresh - yielding another capped token - indefinitely.

2. **Concurrency amplifier.** `ensureFreshness` has no concurrency guard. Multiple browser tabs, parallel
   API calls, or multiple ti-next pods all read the same stale grant from Redis and independently call KC
   with the same refresh token. KC26's Refresh Token Rotation invalidates the token after the first use,
   causing all concurrent requests to fail with `REFRESH_TOKEN_ERROR / Session not active`.

KC 1.9 was unaffected because it neither enforced the session-cap TTL formula nor had Refresh Token Rotation.
The session-cap formula in KC26 is unconditional for non-offline sessions and cannot be disabled via configuration.

## Fix

Two changes to `middleware/auth-utils/grant-manager.js`.

### Fix 2 - Session-cap detection

Added after the existing refresh-token expiry guards in `ensureFreshness`, before the refresh fetch:

```js
if (!grant.isExpired() && grant.access_token && this.tokenMinTtl) {
  const issuedLifetime = grant.access_token.content.exp - grant.access_token.content.iat;
  if (issuedLifetime < this.tokenMinTtl) {
    return nodeify(Promise.reject(new Error('Session near maximum lifespan: re-login required')), callback);
  }
}
```

When KC issues a capped token (e.g. 88s lifetime with tokenMinTtl=90), `issuedLifetime < tokenMinTtl`
is true the moment the token is minted. Instead of refreshing - which would return another capped token
and repeat the cycle - the promise rejects immediately. `grant-attacher.js` catches the rejection and
calls `next()` without a grant; `protect.js` sees no grant and calls `forceLogin()`. No KC call is made.

The guard is skipped when:
- `grant.isExpired()` is true - token is fully expired; let the normal refresh path handle it
- `grant.access_token` is absent
- `this.tokenMinTtl` is falsy (0 or not configured)

### Fix 1 - Refresh deduplication

Added to the constructor:
```js
this._pendingRefreshes = new Map();
```

Added in `ensureFreshness` after Fix 2, before the refresh fetch:
```js
const refreshJti = grant.refresh_token.content && grant.refresh_token.content.jti;
if (refreshJti && this._pendingRefreshes.has(refreshJti)) {
  return nodeify(this._pendingRefreshes.get(refreshJti), callback);
}
const refreshPromise = fetch(this, handler, options, params);
if (refreshJti) {
  this._pendingRefreshes.set(refreshJti, refreshPromise);
  refreshPromise.then(
    () => this._pendingRefreshes.delete(refreshJti),
    () => this._pendingRefreshes.delete(refreshJti)
  );
}
return nodeify(refreshPromise, callback);
```

N concurrent requests sharing the same refresh token share one in-flight KC call rather than each
issuing their own. The dedup key is `refresh_token.content.jti` (KC26 refresh tokens are JWTs with
a `jti` claim). If `jti` is absent (older KC versions), dedup is skipped and behavior is unchanged.

Entries are removed from the map when the promise settles. The map holds only in-flight requests.
No TTL eviction is added - the map lifecycle mirrors the HTTP request lifecycle.

### How Fix 1 and Fix 2 interact

1. Request arrives with a 480s token, 88s remaining. `willExpireBeforeTimeToLive(90)` = true.
   Fix 2: `exp - iat = 480 >= 90` - check passes, proceed to refresh.
   Fix 1: only 1 KC call issued. All concurrent requests receive the new token with `exp - iat = 88`.

2. Next request with the 88s token. `willExpireBeforeTimeToLive(90)` = true.
   Fix 2: `exp - iat = 88 < 90` - reject immediately, user redirected to re-login.
   Zero KC calls made. Storm is impossible.

## `ensureFreshness` final structure

```
1. !isExpired && !willExpireBeforeTimeToLive → return early (fresh, no refresh needed)
2. no refresh_token → reject
3. refresh_token.isExpired() → reject
4. [Fix 2] !isExpired && exp-iat < tokenMinTtl → reject (session near max lifespan)
5. [Fix 1] _pendingRefreshes.has(jti) → return shared in-flight promise
6. build params / handler / options
7. [Fix 1] register refreshPromise in _pendingRefreshes; clean up on settle
8. return nodeify(fetch(...))
```

## Unit Tests

New file: `test/unit/grant-manager-unit-test.js` using `tape`.
Tests use fabricated JWT payloads - no Keycloak server required.

### Fix 2 cases

| # | Scenario | Expected |
|---|---|---|
| 1 | not expired, `exp-iat=88 < tokenMinTtl=90` | rejects "Session near maximum lifespan" |
| 2 | not expired, `exp-iat=tokenMinTtl=90` (exactly equal) | does not reject (boundary exclusive) |
| 3 | not expired, `exp-iat=89 < tokenMinTtl=90` (one second inside) | rejects |
| 4 | not expired, `exp-iat=480 >= tokenMinTtl=90` | does not reject |
| 5 | not expired, `exp-iat=1` (extreme cap) | rejects |
| 6 | already expired, `exp-iat=88 < tokenMinTtl=90` | does not reject via Fix 2 (falls through) |
| 7 | `tokenMinTtl=0` | check skipped entirely |
| 8 | `tokenMinTtl=undefined` | check skipped entirely |
| 9 | `grant.access_token` absent | check skipped |
| 10 | callback style invocation, capped token | calls `cb(err)`, not unhandled rejection |

### Fix 1 cases

| # | Scenario | Expected |
|---|---|---|
| 1 | two concurrent calls, same grant with `jti` | exactly one fetch issued |
| 2 | three concurrent calls, same grant with `jti` | exactly one fetch issued |
| 3 | concurrent calls where KC returns an error | all callers receive the same rejection |
| 4 | after refresh settles (success), new call with same `jti` | issues a fresh fetch (map cleaned up) |
| 5 | after refresh settles (failure), new call with same `jti` | issues a fresh fetch (map cleaned up) |
| 6 | two simultaneous calls with different `jti` values | two separate fetches issued |
| 7 | grant with no `jti` in refresh token | dedup skipped, each call issues its own fetch |
| 8 | after all concurrent calls settle | `_pendingRefreshes.size === 0` |

## Files Changed

| File | Change |
|---|---|
| `middleware/auth-utils/grant-manager.js` | Fix 1 + Fix 2 in `ensureFreshness`, `_pendingRefreshes` in constructor |
| `test/unit/grant-manager-unit-test.js` | New file - unit tests for Fix 1 and Fix 2 |
| `package.json` | Version `3.4.45` → `3.4.46` |

## Commit Structure (branch `AUT-1462-fix-kc26-refresh-token-storm`)

1. `AUT-1462 Add session-cap detection to prevent KC26 refresh token storm (Fix 2)`
   - `grant-manager.js` Fix 2 + Fix 2 unit tests
2. `AUT-1462 Add refresh deduplication guard for concurrent requests (Fix 1)`
   - `grant-manager.js` Fix 1 + Fix 1 unit tests
3. `AUT-1462 Bump to 3.4.46`
   - `package.json` version bump only

## Not in scope

- Reducing `token-minimum-time-to-live` in ti-next (the frontend summary explicitly recommends against
  this - a short TTL allows a token to pass auth at ti-next and then expire mid-chain at a downstream service)
- Keycloak configuration changes - the session-cap formula is unconditional in KC26
- Increasing SSO Session Max - only reduces frequency, does not eliminate the storm
- Custom KC SPI - unnecessary given the client-side fix is complete
