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
const postAuthMiddleware = require('../../middleware/post-auth');

function buildKeycloakStub () {
  const calls = { getGrantFromCode: [], accessDenied: 0, authenticated: 0 };
  const keycloak = {
    getGrantFromCode: function (code, request, response, redirectUri) {
      calls.getGrantFromCode.push({ code, redirectUri });
      return Promise.resolve({ access_token: {} });
    },
    authenticated: function () {
      calls.authenticated++;
    },
    accessDenied: function () {
      calls.accessDenied++;
    }
  };
  return { keycloak, calls };
}

// Builds a callback request as it arrives back from Keycloak: the original
// protected URL (with auth_callback=1) plus the params Keycloak appends.
function buildCallbackRequest (overrides) {
  const req = {
    hostname: 'app.example',
    protocol: 'https',
    headers: { host: 'app.example' },
    path: '/app/dashboard',
    originalUrl: '/app/dashboard?auth_callback=1&state=abc&code=xyz&session_state=sess',
    query: {
      auth_callback: '1',
      state: 'abc',
      code: 'xyz',
      session_state: 'sess'
    },
    session: {},
    kauth: {}
  };
  Object.assign(req, overrides || {});
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

test('post-auth: calls next() when auth_callback is absent', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = postAuthMiddleware(keycloak);
  const req = buildCallbackRequest({ query: {} });
  const res = buildResponse();
  let nextCalled = false;

  middleware(req, res, () => { nextCalled = true; });

  t.equal(nextCalled, true, 'next() should be called');
  t.equal(calls.getGrantFromCode.length, 0, 'getGrantFromCode should not run');
  t.end();
});

test('post-auth: denies access when Keycloak returns an error', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = postAuthMiddleware(keycloak);
  const req = buildCallbackRequest({ query: { auth_callback: '1', error: 'access_denied' } });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(calls.accessDenied, 1, 'accessDenied should be invoked');
  t.equal(calls.getGrantFromCode.length, 0, 'getGrantFromCode should not run on error');
  t.end();
});

test('post-auth: reconstructs redirect_uri from the callback URL, not the session', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = postAuthMiddleware(keycloak);
  // Session holds a stale/other-tab URI; it must be ignored.
  const req = buildCallbackRequest({ session: { auth_redirect_uri: 'https://app.example/some/other/tab?auth_callback=1' } });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(calls.getGrantFromCode.length, 1, 'getGrantFromCode invoked once');
  t.equal(
    calls.getGrantFromCode[0].redirectUri,
    'https://app.example/app/dashboard?auth_callback=1',
    'redirect_uri reconstructed from callback URL, ignoring the session value'
  );
  t.end();
});

test('post-auth: strips code, state, session_state and iss from the reconstructed redirect_uri', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = postAuthMiddleware(keycloak);
  const req = buildCallbackRequest({
    originalUrl: '/app/account-jobs/?filter=CURRENT_WORK&auth_callback=1&state=s1&code=c1&session_state=ss1&iss=https%3A%2F%2Fkc',
    path: '/app/account-jobs/',
    query: { filter: 'CURRENT_WORK', auth_callback: '1', state: 's1', code: 'c1', session_state: 'ss1', iss: 'https://kc' }
  });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(
    calls.getGrantFromCode[0].redirectUri,
    'https://app.example/app/account-jobs/?filter=CURRENT_WORK&auth_callback=1',
    'original app query params and auth_callback are preserved; Keycloak params removed'
  );
  t.end();
});

test('post-auth: includes port from the host header in the reconstructed redirect_uri', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = postAuthMiddleware(keycloak);
  const req = buildCallbackRequest({ headers: { host: 'app.example:3000' } });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(
    calls.getGrantFromCode[0].redirectUri,
    'https://app.example:3000/app/dashboard?auth_callback=1',
    'reconstructed redirect_uri includes the port'
  );
  t.end();
});

test('post-auth: concurrent callbacks with a shared session each reconstruct their own redirect_uri', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = postAuthMiddleware(keycloak);
  // Both tabs share one session object (the real-world race).
  const sharedSession = { auth_redirect_uri: 'https://app.example/whatever-was-stored-last?auth_callback=1' };

  const reqTab1 = buildCallbackRequest({
    originalUrl: '/app/account-jobs/?filter=CURRENT_WORK&auth_callback=1&code=c1&state=s1&session_state=ss1',
    path: '/app/account-jobs/',
    query: { filter: 'CURRENT_WORK', auth_callback: '1', code: 'c1', state: 's1', session_state: 'ss1' },
    session: sharedSession
  });
  const reqTab2 = buildCallbackRequest({
    originalUrl: '/app/projects/abc/dashboard/translator.htm?auth_callback=1&code=c2&state=s2&session_state=ss2',
    path: '/app/projects/abc/dashboard/translator.htm',
    query: { auth_callback: '1', code: 'c2', state: 's2', session_state: 'ss2' },
    session: sharedSession
  });

  middleware(reqTab1, buildResponse(), () => t.fail('next() should not be called'));
  middleware(reqTab2, buildResponse(), () => t.fail('next() should not be called'));

  t.equal(
    calls.getGrantFromCode[0].redirectUri,
    'https://app.example/app/account-jobs/?filter=CURRENT_WORK&auth_callback=1',
    'tab 1 uses its own callback URL'
  );
  t.equal(
    calls.getGrantFromCode[1].redirectUri,
    'https://app.example/app/projects/abc/dashboard/translator.htm?auth_callback=1',
    'tab 2 uses its own callback URL despite the shared session'
  );
  t.end();
});
