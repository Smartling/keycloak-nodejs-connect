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
const protectMiddleware = require('../../middleware/protect');

function buildKeycloakStub () {
  const calls = { loginUrl: [] };
  const keycloak = {
    redirectToLogin: function () {
      return true;
    },
    loginUrl: function (uuid, redirectUrl) {
      calls.loginUrl.push({ uuid, redirectUrl });
      return 'https://kc.example/auth?redirect_uri=' + encodeURIComponent(redirectUrl);
    }
  };
  return { keycloak, calls };
}

function buildRequest (overrides) {
  const req = {
    hostname: 'app.example',
    protocol: 'https',
    headers: { host: 'app.example' },
    originalUrl: '/app/dashboard',
    session: {}
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

test('protect: percent-encodes [ and ] in the redirect_uri query string', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = protectMiddleware(keycloak);
  const req = buildRequest({
    originalUrl: '/app/account-jobs/?filter=CURRENT_WORK&accountUids[]=c662b7a3&workflowStepTypes[]=TRANSLATION'
  });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(
    calls.loginUrl[0].redirectUrl,
    'https://app.example/app/account-jobs/?filter=CURRENT_WORK&accountUids%5B%5D=c662b7a3&workflowStepTypes%5B%5D=TRANSLATION&auth_callback=1',
    'brackets in query params are percent-encoded before being sent to Keycloak'
  );
  t.end();
});

test('protect: percent-encodes { and } in the redirect_uri query string', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = protectMiddleware(keycloak);
  const req = buildRequest({
    originalUrl: '/app/dashboard?token={abc}'
  });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(
    calls.loginUrl[0].redirectUrl,
    'https://app.example/app/dashboard?token=%7Babc%7D&auth_callback=1',
    'braces in query params are percent-encoded before being sent to Keycloak'
  );
  t.end();
});

test('protect: leaves already-percent-encoded sequences untouched', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = protectMiddleware(keycloak);
  const req = buildRequest({
    originalUrl: '/app/dashboard?redirect=%2Fhome%2Fpage'
  });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(
    calls.loginUrl[0].redirectUrl,
    'https://app.example/app/dashboard?redirect=%2Fhome%2Fpage&auth_callback=1',
    'existing percent-encoded sequences are not re-encoded'
  );
  t.end();
});

test('protect: does not alter the pathname', t => {
  const { keycloak, calls } = buildKeycloakStub();
  const middleware = protectMiddleware(keycloak);
  const req = buildRequest({
    originalUrl: '/app/dashboard'
  });
  const res = buildResponse();

  middleware(req, res, () => t.fail('next() should not be called'));

  t.equal(
    calls.loginUrl[0].redirectUrl,
    'https://app.example/app/dashboard?auth_callback=1',
    'no query string means no encoding changes and auth_callback is appended with ?'
  );
  t.end();
});
