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

function buildRequest ({ xhr = false, acceptsHtml = true, originalUrl } = {}) {
  return {
    hostname: 'app.example',
    protocol: 'https',
    headers: { host: 'app.example' },
    query: {},
    kauth: {},
    xhr,
    originalUrl,
    accepts: (type) => acceptsHtml && type === 'text/html'
  };
}

function buildResponse () {
  const redirects = [];
  return {
    redirect: (url) => { redirects.push(url); },
    _redirects: redirects
  };
}

function buildKeycloakStub ({ getGrantResult } = {}) {
  const deauthCalls = [];
  const keycloak = {
    getGrant: () => getGrantResult,
    logoutUrl: (redirectUrl, idTokenHint) => {
      return 'https://keycloak.example/logout?redirect=' + encodeURIComponent(redirectUrl) +
        (idTokenHint ? '&id_token_hint=' + encodeURIComponent(idTokenHint) : '');
    },
    deauthenticated: (req) => { deauthCalls.push(req); }
  };
  return { keycloak, deauthCalls };
}

// Builds a SessionExpiredError whose .grant has already been wrapped by getGrant
// (i.e. has a working unstore method), matching what index.js produces.
function buildSessionExpiredError ({ idTokenHint } = {}) {
  const unstoreCalls = [];
  const grant = {
    id_token: idTokenHint ? { token: idTokenHint } : undefined,
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

test('grant-attacher: SessionExpiredError triggers RP-initiated logout redirect', t => {
  const err = buildSessionExpiredError({ idTokenHint: 'id.token.hint' });
  const { keycloak, deauthCalls } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => { t.fail('next() should not be called'); });

  setTimeout(() => {
    t.equal(res._redirects.length, 1, 'one redirect issued');
    t.ok(res._redirects[0].includes('id_token_hint='), 'redirect URL includes id_token_hint');
    t.equal(err._unstoreCalls.length, 1, 'grant.unstore was called to clear the session');
    t.equal(deauthCalls.length, 1, 'keycloak.deauthenticated was called');
    t.end();
  }, 10);
});

test('grant-attacher: SessionExpiredError without idTokenHint still redirects to logout', t => {
  const err = buildSessionExpiredError({ idTokenHint: undefined });
  const { keycloak, deauthCalls } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => { t.fail('next() should not be called'); });

  setTimeout(() => {
    t.equal(res._redirects.length, 1, 'one redirect issued');
    t.notOk(res._redirects[0].includes('id_token_hint='), 'no id_token_hint when hint is absent');
    t.equal(err._unstoreCalls.length, 1, 'grant.unstore was called');
    t.equal(deauthCalls.length, 1, 'keycloak.deauthenticated was called');
    t.end();
  }, 10);
});

test('grant-attacher: SessionExpiredError with unwrapped grant skips unstore but still redirects', t => {
  // Simulates the bearer-only edge case: getGrant skips wrap when stores.length < 2,
  // so err.grant exists but has no unstore method.
  const err = new SessionExpiredError({ id_token: undefined }); // grant without unstore — not wrapped
  const { keycloak, deauthCalls } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => { t.fail('next() should not be called'); });

  setTimeout(() => {
    t.equal(res._redirects.length, 1, 'redirect issued even without wrapped grant');
    t.equal(deauthCalls.length, 0, 'deauthenticated not called when grant has no unstore');
    t.end();
  }, 10);
});

test('grant-attacher: SessionExpiredError redirect URL uses request protocol and hostname', t => {
  const err = buildSessionExpiredError({ idTokenHint: undefined });
  const { keycloak } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest();
  req.protocol = 'https';
  req.hostname = 'myapp.example';
  req.headers = { host: 'myapp.example:3000' };
  const res = buildResponse();

  middleware(req, res, () => { t.fail('next() should not be called'); });

  setTimeout(() => {
    t.ok(res._redirects[0].includes(encodeURIComponent('https://myapp.example:3000/')),
      'redirect URL includes correct origin with port');
    t.end();
  }, 10);
});

test('grant-attacher: SessionExpiredError redirect preserves the original deep-linked URL', t => {
  const err = buildSessionExpiredError({ idTokenHint: undefined });
  const { keycloak } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest({ originalUrl: '/app/84c012a33?locale=fr&start=0' });
  const res = buildResponse();

  middleware(req, res, () => { t.fail('next() should not be called'); });

  setTimeout(() => {
    t.ok(
      res._redirects[0].includes(encodeURIComponent('https://app.example/app/84c012a33?locale=fr&start=0')),
      'post_logout_redirect_uri should be the originally-requested deep link, not the site root'
    );
    t.end();
  }, 10);
});

test('grant-attacher: SessionExpiredError on XHR request calls next() without redirecting', t => {
  const err = buildSessionExpiredError({ idTokenHint: 'id.token.hint' });
  const { keycloak } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest({ xhr: true });
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(res._redirects.length, 0, 'no redirect for XHR request');
    t.end();
  });
});

test('grant-attacher: SessionExpiredError on API request (no text/html) calls next() without redirecting', t => {
  const err = buildSessionExpiredError({ idTokenHint: 'id.token.hint' });
  const { keycloak } = buildKeycloakStub({ getGrantResult: Promise.reject(err) });
  const middleware = grantAttacherMiddleware(keycloak);
  const req = buildRequest({ acceptsHtml: false });
  const res = buildResponse();

  middleware(req, res, () => {
    t.equal(res._redirects.length, 0, 'no redirect for non-HTML request');
    t.end();
  });
});
