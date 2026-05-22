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
const logoutMiddleware = require('../../middleware/logout');

function buildKeycloakStub () {
  const calls = { logoutUrl: [], deauthenticated: 0 };
  const keycloak = {
    logoutUrl: function (redirectUrl, idTokenHint) {
      calls.logoutUrl.push({ redirectUrl, idTokenHint });
      return 'http://keycloak.example/logout?redirect_uri=' +
        encodeURIComponent(redirectUrl) +
        (idTokenHint ? '&id_token_hint=' + encodeURIComponent(idTokenHint) : '');
    },
    deauthenticated: function () {
      calls.deauthenticated++;
    }
  };
  return { keycloak, calls };
}

function buildRequest (overrides) {
  const unstoreCalls = [];
  const req = {
    path: '/logout',
    hostname: 'app.example',
    protocol: 'http',
    headers: { host: 'app.example' },
    query: {},
    kauth: {
      grant: {
        id_token: { token: 'header.payload.sig' },
        unstore: function (request, response) {
          unstoreCalls.push({ request, response });
        }
      }
    }
  };
  Object.assign(req, overrides || {});
  req._unstoreCalls = unstoreCalls;
  return req;
}

function buildResponse () {
  const redirects = [];
  return {
    redirect: function (url) {
      redirects.push(url);
    },
    _redirects: redirects
  };
}

test('logout middleware: calls next() when path does not match', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = logoutMiddleware(keycloak, '/logout');
  const req = buildRequest({ path: '/other' });
  const res = buildResponse();
  let nextCalled = false;

  middleware(req, res, () => { nextCalled = true; });

  t.equal(nextCalled, true, 'next() should be called');
  t.equal(calls.logoutUrl.length, 0, 'logoutUrl should not be invoked');
  t.equal(res._redirects.length, 0, 'no redirect should occur');
  t.end();
});

test('logout middleware: passes id_token to logoutUrl before clearing the grant', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = logoutMiddleware(keycloak, '/logout');
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(calls.logoutUrl.length, 1, 'logoutUrl invoked once');
  t.equal(calls.logoutUrl[0].idTokenHint, 'header.payload.sig', 'id_token captured from grant before unstore');
  t.equal(calls.deauthenticated, 1, 'deauthenticated should be invoked');
  t.equal(req._unstoreCalls.length, 1, 'grant.unstore should be invoked');
  t.equal(req.kauth.grant, undefined, 'grant should be removed after logout');
  t.end();
});

test('logout middleware: does not throw when grant has no id_token', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = logoutMiddleware(keycloak, '/logout');
  const req = buildRequest();
  delete req.kauth.grant.id_token;
  const res = buildResponse();

  t.doesNotThrow(() => {
    middleware(req, res, () => t.fail('next() should not be called'));
  });
  t.equal(calls.logoutUrl[0].idTokenHint, undefined, 'idTokenHint should be undefined when id_token is missing');
  t.end();
});

test('logout middleware: builds redirect URL from request.protocol/hostname when no query.redirectUrl', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = logoutMiddleware(keycloak, '/logout');
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(calls.logoutUrl[0].redirectUrl, 'http://app.example/', 'default redirect URL uses protocol + hostname + /');
  t.end();
});

test('logout middleware: includes port in default redirect URL when present in host header', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = logoutMiddleware(keycloak, '/logout');
  const req = buildRequest({ headers: { host: 'app.example:3000' } });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(calls.logoutUrl[0].redirectUrl, 'http://app.example:3000/', 'redirect URL should include port');
  t.end();
});

test('logout middleware: uses query.redirectUrl when provided', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = logoutMiddleware(keycloak, '/logout');
  const req = buildRequest({ query: { redirectUrl: 'http://elsewhere.example/done' } });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(calls.logoutUrl[0].redirectUrl, 'http://elsewhere.example/done', 'query.redirectUrl should be used');
  t.end();
});

test('logout middleware: redirects to URL produced by keycloak.logoutUrl', t => {
  const { keycloak } = buildKeycloakStub();
  const middleware = logoutMiddleware(keycloak, '/logout');
  const req = buildRequest();
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(res._redirects.length, 1, 'one redirect should be issued');
  t.equal(res._redirects[0].indexOf('id_token_hint=') > 0, true, 'redirect URL should contain id_token_hint');
  t.end();
});
