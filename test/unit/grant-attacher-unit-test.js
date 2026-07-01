/*
 * Copyright 2016 Red Hat Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
'use strict';

const test = require('tape');
const grantAttacherMiddleware = require('../../middleware/grant-attacher');
const { SessionExpiredError } = require('../../middleware/auth-utils/errors');

function buildRequest () {
  return {
    hostname: 'app.example',
    protocol: 'https',
    headers: { host: 'app.example' },
    query: {},
    kauth: {}
  };
}

function buildResponse () {
  const redirects = [];
  return {
    redirect: (url) => { redirects.push(url); },
    _redirects: redirects
  };
}

function buildKeycloakStub ({ getGrantResult, logoutResult } = {}) {
  const deauthCalls = [];
  const logoutCalls = [];
  const keycloak = {
    getGrant: () => getGrantResult,
    deauthenticated: (req) => { deauthCalls.push(req); },
    grantManager: {
      logout: (grant) => {
        logoutCalls.push(grant);
        return logoutResult !== undefined ? logoutResult : Promise.resolve();
      }
    }
  };
  return { keycloak, deauthCalls, logoutCalls };
}

// Builds a SessionExpiredError whose .grant has already been wrapped by getGrant
// (i.e. has a working unstore method), matching what index.js produces.
function buildSessionExpiredError () {
  const unstoreCalls = [];
  const grant = {
    refresh_token: { token: 'fake-refresh-token' },
    unstore: (req, res) => { unstoreCalls.push({ req, res }); }
  };
  const err = new SessionExpiredError(grant);
  err._unstoreCalls = unstoreCalls;
  return err;
}

test('grant-attacher: attaches grant and calls next() on success', t => {
  const fakeGrant = { access_token: {} };
  const { keycloak } = buildKeycloakStub({ getGrantResult: Promise.resolve(fakeGrant) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(req.kauth.grant, fakeGrant, 'grant is set on request.kauth');
    t.equal(res._redirects.length, 0, 'no redirect should occur');
    t.end();
  });
});

test('grant-attacher: calls next() and logs on generic error', t => {
  const { keycloak } = buildKeycloakStub({ getGrantResult: Promise.reject(new Error('token invalid')) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(req.kauth.grant, undefined, 'grant is not set');
    t.equal(res._redirects.length, 0, 'no redirect on generic error');
    t.end();
  });
});

test('grant-attacher: calls next() silently when getGrant rejects with no error', t => {
  const { keycloak } = buildKeycloakStub({ getGrantResult: Promise.reject() });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(res._redirects.length, 0, 'no redirect');
    t.end();
  });
});

test('grant-attacher: SessionExpiredError triggers back-channel logout and calls next()', t => {
  const err = buildSessionExpiredError();
  const { keycloak, deauthCalls, logoutCalls } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(logoutCalls.length, 1, 'grantManager.logout called with the expired grant');
    t.equal(err._unstoreCalls.length, 1, 'grant.unstore called to clear local session');
    t.equal(deauthCalls.length, 1, 'keycloak.deauthenticated called');
    t.equal(res._redirects.length, 0, 'no redirect — downstream middleware handles re-auth');
    t.end();
  });
});

test('grant-attacher: SessionExpiredError without grant just calls next()', t => {
  const err = new SessionExpiredError(undefined);
  const { keycloak, deauthCalls, logoutCalls } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(logoutCalls.length, 0, 'no logout call when grant is absent');
    t.equal(deauthCalls.length, 0, 'no deauthenticated call when grant is absent');
    t.end();
  });
});

test('grant-attacher: SessionExpiredError with grant missing unstore skips unstore but still logs out', t => {
  const grant = { refresh_token: { token: 'fake-refresh-token' } }; // no unstore
  const err = new SessionExpiredError(grant);
  const { keycloak, deauthCalls, logoutCalls } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(logoutCalls.length, 1, 'back-channel logout still called');
    t.equal(deauthCalls.length, 1, 'deauthenticated still called');
    t.end();
  });
});

test('grant-attacher: back-channel logout failure does not prevent next() from being called', t => {
  const err = buildSessionExpiredError();
  const { keycloak } = buildKeycloakStub({
    getGrantResult: Promise.reject(err),
    logoutResult: Promise.reject(new Error('KC unreachable'))
  });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => {
    t.pass('next() called even when back-channel logout fails');
    t.end();
  });
});

test('grant-attacher: SessionExpiredError on XHR request also triggers back-channel logout', t => {
  const err = buildSessionExpiredError();
  const { keycloak, logoutCalls } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = Object.assign(buildRequest(), { xhr: true });
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(logoutCalls.length, 1, 'back-channel logout called for XHR requests too');
    t.equal(res._redirects.length, 0, 'no redirect for XHR request');
    t.end();
  });
});
