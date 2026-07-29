/*!
 * Copyright 2014 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const URL = require('url');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const querystring = require('querystring');
const Grant = require('./grant');
const Token = require('./token');
var Rotation = require('./rotation');
const { SessionExpiredError } = require('./errors');

/**
 * Construct a grant manager.
 *
 * @param {Config} config Config object.
 *
 * @constructor
 */
function GrantManager (config) {
  this.realmUrl = config.realmUrl;
  this.clientId = config.clientId;
  this.secret = config.secret;
  this.publicKey = config.publicKey;
  this.public = config.public;
  this.bearerOnly = config.bearerOnly;
  this.notBefore = 0;
  this.rotation = new Rotation(config);
  this.tokenMinTtl = config.tokenMinTtl;
  this.refreshCoordinator = config.refreshCoordinator;
  this._pendingRefreshes = new Map();
}

// Coordination TTLs for `refreshCoordinator`-backed cross-instance dedup (see `_coordinated`).
// A real HTTP round-trip to Keycloak normally completes in well under a second; these are
// safety-net bounds for a claim-holder that crashes before publishing a result.
const COORDINATION_LOCK_TTL_MS = 5000;
const COORDINATION_RESULT_TTL_MS = 15000;
const COORDINATION_WAIT_TIMEOUT_MS = 5000;
// The leader renews its claim this often while doFetch is in flight (see
// _leadWithHeartbeat), so a live leader's claim never lapses mid-operation - only a
// leader that's stopped renewing (crashed, or finished) ever lets it expire.
const HEARTBEAT_INTERVAL_MS = Math.floor(COORDINATION_LOCK_TTL_MS / 3);
// Purely a defensive cap against pathological Redis flakiness (e.g. claim() never
// succeeding). With heartbeating, a lapsed claim unambiguously means the leader is gone,
// so re-running the claim/await cycle needs no "how many times do we guess" budget - this
// just stops a follower from recursing forever if the coordinator itself is unusable.
const COORDINATION_RECLAIM_DEPTH_LIMIT = 5;
const COORDINATION_RECLAIM_JITTER_MAX_MS = 25;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Use the direct grant API to obtain a grant from Keycloak.
 *
 * The direct grant API must be enabled for the configured realm
 * for this method to work. This function ostensibly provides a
 * non-interactive, programatic way to login to a Keycloak realm.
 *
 * This method can either accept a callback as the last parameter
 * or return a promise.
 *
 * @param {String} username The username.
 * @param {String} password The cleartext password.
 * @param {Function} callback Optional callback, if not using promises.
 */
GrantManager.prototype.obtainDirectly = function obtainDirectly (username, password,
  callback, scopeParam) {
  const params = {
    client_id: this.clientId,
    username: username,
    password: password,
    grant_type: 'password',
    scope: scopeParam || 'openid'
  };
  const handler = createHandler(this);
  const options = postOptions(this);
  return nodeify(fetch(this, handler, options, params), callback);
};

/**
 * Obtain a grant from a previous interactive login which results in a code.
 *
 * This is typically used by servers which receive the code through a
 * redirect_uri when sending a user to Keycloak for an interactive login.
 *
 * An optional session ID and host may be provided if there is desire for
 * Keycloak to be aware of this information.  They may be used by Keycloak
 * when session invalidation is triggered from the Keycloak console itself
 * during its postbacks to `/k_logout` on the server.
 *
 * This method returns or promise or may optionally take a callback function.
 *
 * @param {String} code The code from a successful login redirected from Keycloak.
 * @param {String} sessionId Optional opaque session-id.
 * @param {String} sessionHost Optional session host for targetted Keycloak console post-backs.
 * @param {String} redirectUri The redirect_uri reconstructed from the callback URL. Must match the
 *   redirect_uri used on the authorization request. Falls back to the legacy session value if omitted.
 * @param {Function} callback Optional callback, if not using promises.
 */
GrantManager.prototype.obtainFromCode = function obtainFromCode (request, code, sessionId, sessionHost, redirectUri, callback) {
  const params = {
    client_session_state: sessionId,
    client_session_host: sessionHost,
    code: code,
    grant_type: 'authorization_code',
    client_id: this.clientId,
    redirect_uri: redirectUri || (request.session ? request.session.auth_redirect_uri : {})
  };
  const options = postOptions(this);
  const doFetch = () => fetch(this, rawJsonHandler, options, params);

  const promise = this.refreshCoordinator
    ? this._coordinated('kc-code:' + code, doFetch).then(json => this.createGrant(json))
    : doFetch().then(json => this.createGrant(json));

  return nodeify(promise, callback);
};

/**
 * Obtain a service account grant.
 * Client option 'Service Accounts Enabled' needs to be on.
 *
 * This method returns or promise or may optionally take a callback function.
 *
 * @param {Function} callback Optional callback, if not using promises.
 */
GrantManager.prototype.obtainFromClientCredentials = function obtainFromlientCredentials (callback, scopeParam) {
  const params = {
    grant_type: 'client_credentials',
    scope: scopeParam || 'openid',
    client_id: this.clientId
  };
  const handler = createHandler(this);
  const options = postOptions(this);

  return nodeify(fetch(this, handler, options, params), callback);
};

/**
 * Ensure that a grant is *fresh*, refreshing if required & possible.
 *
 * If the access_token is not expired, the grant is left untouched.
 *
 * If the access_token is expired, and a refresh_token is available,
 * the grant is refreshed, in place (no new object is created),
 * and returned.
 *
 * If the access_token is expired and no refresh_token is available,
 * an error is provided.
 *
 * The method may either return a promise or take an optional callback.
 *
 * @param {Grant} grant The grant object to ensure freshness of.
 * @param {Function} callback Optional callback if promises are not used.
 */
GrantManager.prototype.ensureFreshness = function ensureFreshness (grant, callback) {
  if (!grant.isExpired() && !grant.willTokenExpireBeforeTimeToLive(this.tokenMinTtl)) {
    return nodeify(Promise.resolve(grant), callback);
  }

  if (!grant.refresh_token) {
    return nodeify(Promise.reject(new Error('Unable to refresh without a refresh token')), callback);
  }

  if (grant.refresh_token.isExpired()) {
    return nodeify(Promise.reject(new Error('Unable to refresh with expired refresh token')), callback);
  }

  if (!grant.isExpired() && grant.access_token && this.tokenMinTtl) {
    // KC26 caps token lifetime to min(configuredLifespan, remainingSessionTime) near session end.
    // A normal token has exp-iat == configuredLifespan (e.g. 480s). A session-capped token has a
    // shorter issued lifetime. When issuedLifetime < tokenMinTtl the session is so close to its
    // maximum lifespan that another refresh would only produce another capped token — redirect to
    // login instead.
    const issuedLifetime = grant.access_token.content.exp - grant.access_token.content.iat;
    if (issuedLifetime < this.tokenMinTtl) {
      return nodeify(Promise.reject(new SessionExpiredError(grant)), callback);
    }
  }

  const params = {
    grant_type: 'refresh_token',
    refresh_token: grant.refresh_token.token
  };
  const options = postOptions(this);

  const refreshJti = grant.refresh_token.content?.jti;
  if (refreshJti && this._pendingRefreshes.has(refreshJti)) {
    return nodeify(this._pendingRefreshes.get(refreshJti), callback);
  }

  const doFetch = () => fetch(this, rawJsonHandler, options, params);
  const refreshPromise = (refreshJti && this.refreshCoordinator)
    ? this._coordinated('kc-refresh:' + refreshJti, doFetch).then(json => this.createGrant(json))
    : doFetch().then(json => this.createGrant(json));

  if (refreshJti) {
    this._pendingRefreshes.set(refreshJti, refreshPromise);
    refreshPromise.then(
      () => this._pendingRefreshes.delete(refreshJti),
      () => this._pendingRefreshes.delete(refreshJti)
    );
  }

  return nodeify(refreshPromise, callback);
};

/**
 * Coordinate a Keycloak-session-touching operation (refresh or code exchange) across
 * multiple app instances via the configured `refreshCoordinator`, so only one instance
 * performs the actual request while others share its result instead of independently
 * racing Keycloak for the same code/refresh-token.
 *
 * The winner of `claim()` leads: it performs `doFetch` while renewing its claim on a
 * heartbeat (see `_leadWithHeartbeat`), so the claim can't lapse while it's genuinely
 * still working. Losers `await()` the leader's published result. If a claim does lapse
 * (the leader crashed or finished without publishing), `await()` resolves with `null` and
 * this re-runs the whole claim/await cycle - Redis's atomic claim still arbitrates a
 * single new leader among any followers re-claiming at once - bounded by
 * `COORDINATION_RECLAIM_DEPTH_LIMIT` purely as a defensive cap against pathological
 * coordinator flakiness, not because a lapsed claim is ambiguous. Falls back to calling
 * `doFetch` directly whenever the coordinator itself is unusable (`claim`/`await`
 * rejecting) or once that depth limit is exhausted.
 *
 * @param {String} key Coordination key, unique to the code/refresh-token being exchanged.
 * @param {Function} doFetch () => Promise<String> resolving the raw Keycloak response body.
 * @param {Number} [depth] Internal recursion counter - callers should omit this.
 * @return {Promise<String>} the raw Keycloak response body (from this or another instance).
 */
GrantManager.prototype._coordinated = function _coordinated (key, doFetch, depth) {
  depth = depth || 0;
  const coordinator = this.refreshCoordinator;

  return coordinator.claim(key, COORDINATION_LOCK_TTL_MS).then(token => {
    if (token) {
      return this._leadWithHeartbeat(coordinator, key, token, doFetch);
    }

    return coordinator.await(key, COORDINATION_WAIT_TIMEOUT_MS).then(result => {
      if (result === null) {
        if (depth >= COORDINATION_RECLAIM_DEPTH_LIMIT) return doFetch();
        return sleep(Math.random() * COORDINATION_RECLAIM_JITTER_MAX_MS)
          .then(() => this._coordinated(key, doFetch, depth + 1));
      }
      if (result.ok) return result.json;
      return Promise.reject(new Error(result.message));
    }, () => doFetch());
  }, () => doFetch());
};

/**
 * Performs `doFetch` as the leader of `key`'s claim, renewing it on a timer
 * (`HEARTBEAT_INTERVAL_MS`) for as long as `doFetch` is pending, then publishes the
 * outcome for any followers awaiting it. The heartbeat always stops before this settles -
 * on success, on failure, or the moment a renewal reports the claim was preempted.
 *
 * @param {Object} coordinator The configured `refreshCoordinator`.
 * @param {String} key Coordination key.
 * @param {String} token Ownership token from the `claim()` that made us leader.
 * @param {Function} doFetch () => Promise<String> resolving the raw Keycloak response body.
 * @return {Promise<String>} the raw Keycloak response body.
 */
GrantManager.prototype._leadWithHeartbeat = function _leadWithHeartbeat (coordinator, key, token, doFetch) {
  const interval = setInterval(() => {
    coordinator.renew(key, token, COORDINATION_LOCK_TTL_MS).then(stillOwner => {
      if (!stillOwner) clearInterval(interval);
    }, () => { /* transient renew failure just costs one skipped beat, not the lease */ });
  }, HEARTBEAT_INTERVAL_MS);

  return doFetch().then(
    json => {
      clearInterval(interval);
      return coordinator.publish(key, { ok: true, json: json }, COORDINATION_RESULT_TTL_MS, token)
        .catch(() => {}).then(() => json);
    },
    err => {
      clearInterval(interval);
      return coordinator.publish(key, { ok: false, message: err.message }, COORDINATION_RESULT_TTL_MS, token)
        .catch(() => {}).then(() => Promise.reject(err));
    }
  );
};

/**
 * Perform live validation of an `access_token` against the Keycloak server.
 *
 * @param {Token|String} token The token to validate.
 * @param {Function} callback Callback function if not using promises.
 *
 * @return {boolean} `false` if the token is invalid, or the same token if valid.
 */
GrantManager.prototype.validateAccessToken = function validateAccessToken (token, callback) {
  let t = token;
  if (typeof token === 'object') {
    t = token.token;
  }
  const params = {
    token: t,
    client_secret: this.secret,
    client_id: this.clientId
  };
  const options = postOptions(this, '/protocol/openid-connect/token/introspect');
  const handler = validationHandler(this, token);

  return nodeify(fetch(this, handler, options, params), callback);
};

GrantManager.prototype.userInfo = function userInfo (token, callback) {
  const url = this.realmUrl + '/protocol/openid-connect/userinfo';
  const options = URL.parse(url);
  options.method = 'GET';

  let t = token;
  if (typeof token === 'object') t = token.token;

  options.headers = {
    'Authorization': 'Bearer ' + t,
    'Accept': 'application/json',
    'X-Client': 'keycloak-nodejs-connect'
  };

  const promise = new Promise((resolve, reject) => {
    const req = getProtocol(options).request(options, (response) => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return reject(new Error('Error fetching account'));
      }
      let json = '';
      response.on('data', (d) => (json += d.toString()));
      response.on('end', () => {
        const data = JSON.parse(json);
        if (data.error) reject(data);
        else resolve(data);
      });
    });
    req.on('error', reject);
    req.end();
  });

  return nodeify(promise, callback);
};

GrantManager.prototype.getAccount = function getAccount () {
  console.error('GrantManager#getAccount is deprecated. See GrantManager#userInfo');
  return this.userInfo.apply(this, arguments);
};

GrantManager.prototype.isGrantRefreshable = function isGrantRefreshable (grant) {
  return !this.bearerOnly && (grant && grant.refresh_token);
};

/**
 * Create a `Grant` object from a string of JSON data.
 *
 * This method creates the `Grant` object, including
 * the `access_token`, `refresh_token` and `id_token`
 * if available, and validates each for expiration and
 * against the known public-key of the server.
 *
 * @param {String} rawData The raw JSON string received from the Keycloak server or from a client.
 * @return {Promise} A promise reoslving a grant.
 */
GrantManager.prototype.createGrant = function createGrant (rawData) {
  let grantData = rawData;
  if (typeof rawData !== 'object') grantData = JSON.parse(grantData);

  const grant = new Grant({
    access_token: (grantData.access_token ? new Token(grantData.access_token, this.clientId) : undefined),
    refresh_token: (grantData.refresh_token ? new Token(grantData.refresh_token) : undefined),
    id_token: (grantData.id_token ? new Token(grantData.id_token) : undefined),
    expires_in: grantData.expires_in,
    token_type: grantData.token_type,
    __raw: rawData
  });

  if (this.isGrantRefreshable(grant)) {
    return new Promise((resolve, reject) => {
      this.ensureFreshness(grant)
        .then(g => this.validateGrant(g))
        .then(g => resolve(g))
        .catch(err => reject(err));
    });
  } else {
    return this.validateGrant(grant);
  }
};

/**
 * Validate the grant and all tokens contained therein.
 *
 * This method examines a grant (in place) and rejects
 * if any of the tokens are invalid. After this method
 * resolves, the passed grant is guaranteed to have
 * valid tokens.
 *
 * @param {Grant} The grant to validate.
 *
 * @return {Promise} That resolves to a validated grant or
 * rejects with an error if any of the tokens are invalid.
 */
GrantManager.prototype.validateGrant = function validateGrant (grant) {
  var self = this;
  const validateGrantToken = (grant, tokenName) => {
    return new Promise((resolve, reject) => {
    // check the access token
      this.validateToken(grant[tokenName]).then(token => {
        grant[tokenName] = token;
        resolve();
      }).catch((err) => {
        reject(new Error('Grant validation failed. Reason: ' + err.message));
      });
    });
  };
  return new Promise((resolve, reject) => {
    var promises = [];
    promises.push(validateGrantToken(grant, 'access_token'));
    if (!self.bearerOnly) {
      if (grant.refresh_token) {
        promises.push(validateGrantToken(grant, 'refresh_token'));
      }
      if (grant.id_token) {
        promises.push(validateGrantToken(grant, 'id_token'));
      }
    }
    Promise.all(promises).then(() => {
      resolve(grant);
    }).catch((err) => {
      reject(new Error(err.message));
    });
  });
};

/**
 * Validate a token.
 *
 * This method accepts a token, and returns a promise
 *
 * If the token is valid the promise will be resolved with the token
 *
 * If any of the following errors are seen the promise will resolve with undefined:
 *
 * - The token was undefined in the first place.
 * - The token is expired.
 * - The token is not expired, but issued before the current *not before* timestamp.
 * - The token signature does not verify against the known realm public-key.
 *
 * @return {Promise} That resolve a token
 */
GrantManager.prototype.validateToken = function validateToken (token) {
  return new Promise((resolve, reject) => {
    if (!token) {
      reject(new Error('invalid token (missing)'));
    } else if (token.isExpired()) {
      reject(new Error('invalid token (expired)'));
    } else if (!token.signed) {
      reject(new Error('invalid token (not signed)'));
    } else if (token.content.iat < this.notBefore) {
      reject(new Error('invalid token (future dated)'));
    } else if (token.content.iss !== this.realmUrl) {
      reject(new Error('invalid token (wrong ISS)'));
    } else {
      // KC26 internal tokens (e.g. refresh_token) are HS512-signed with a
      // realm-side secret that clients never have. Skip RSA verification —
      // KC will validate the token when it is presented for refresh.
      if (token.header && token.header.alg && token.header.alg.startsWith('HS')) {
        return resolve(token);
      }
      const verify = crypto.createVerify('RSA-SHA256');
      // if public key has been supplied use it to validate token
      if (this.publicKey) {
        try {
          verify.update(token.signed);
          if (!verify.verify(this.publicKey, token.signature, 'base64')) {
            reject(new Error('invalid token (signature)'));
          } else {
            resolve(token);
          }
        } catch (err) {
          reject(new Error('Misconfigured parameters while validating token. Check your keycloak.json file!'));
        }
      } else {
        // retrieve public KEY and use it to validate token
        this.rotation.getJWK(token.header.kid).then(key => {
          verify.update(token.signed);
          if (!verify.verify(key, token.signature)) {
            reject(new Error('invalid token (public key signature)'));
          } else {
            resolve(token);
          }
        }).catch((err) => {
          reject(new Error('failed to load public key to verify token. Reason: ' + err));
        });
      }
    }
  });
};

const getProtocol = (opts) => {
  return opts.protocol === 'https:' ? https : http;
};

const nodeify = (promise, cb) => {
  if (typeof cb !== 'function') return promise;
  return promise.then((res) => cb(null, res)).catch((err) => cb(err));
};

const createHandler = (manager) => (resolve, reject, json) => {
  try {
    resolve(manager.createGrant(json));
  } catch (err) {
    reject(err);
  }
};

const rawJsonHandler = (resolve, reject, json) => resolve(json);

const validationHandler = (manager, token) => (resolve, reject, json) => {
  const data = JSON.parse(json);
  if (!data.active) resolve(false);
  else resolve(token);
};

const postOptions = (manager, path) => {
  const realPath = path || '/protocol/openid-connect/token';
  const opts = URL.parse(manager.realmUrl + realPath);
  opts.headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Client': 'keycloak-nodejs-connect'
  };
  if (!manager.public) {
    opts.headers.Authorization = 'Basic ' + new Buffer(manager.clientId + ':' + manager.secret).toString('base64');
  }
  opts.method = 'POST';
  return opts;
};

const fetch = (manager, handler, options, params) => {
  return new Promise((resolve, reject) => {
    const data = (typeof params === 'string' ? params : querystring.stringify(params));
    options.headers['Content-Length'] = data.length;

    const req = getProtocol(options).request(options, (response) => {
      let json = '';
      response.on('data', (d) => (json += d.toString()));
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode > 299) {
          const grantType = typeof params === 'object' ? (params.grant_type || '') : '';
          const req = `${options.method}:${options.path} ${grantType}`;
          const resp = `${response.statusCode}: ${http.STATUS_CODES[response.statusCode]} ${json}`;
          reject(new Error(resp + ' on ' + req));
        } else {
          handler(resolve, reject, json);
        }
      });
    });

    req.write(data);
    req.on('error', reject);
    req.end();
  });
};

GrantManager.prototype.logout = function logout (grant) {
  const params = {
    client_id: this.clientId,
    refresh_token: grant.refresh_token && grant.refresh_token.token
  };
  return fetch(
    this,
    (resolve) => resolve(),
    postOptions(this, '/protocol/openid-connect/logout'),
    params
  );
};

module.exports = GrantManager;
