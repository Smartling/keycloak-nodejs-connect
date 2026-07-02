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

const UUID = require('./../uuid');

// Characters browsers commonly leave unencoded in a query string (per the WHATWG URL
// spec) but that Keycloak's server-side URI builder percent-encodes when it reconstructs
// the redirect_uri to build the post-login Location header. If we send them unencoded on
// the initial /auth request, Keycloak's saved copy no longer matches the encoded form it
// hands back later, and the code-to-token exchange fails with invalid_redirect_uri. Encode
// them here so both copies are identical from the start. See AUT-1461.
const KEYCLOAK_QUERY_UNSAFE_CHARS = /[[\]{}]/g;
const KEYCLOAK_QUERY_UNSAFE_CHAR_ENCODINGS = { '[': '%5B', ']': '%5D', '{': '%7B', '}': '%7D' };

function encodeUnsafeQueryChars (queryString) {
  return queryString.replace(KEYCLOAK_QUERY_UNSAFE_CHARS, (char) => KEYCLOAK_QUERY_UNSAFE_CHAR_ENCODINGS[char]);
}

function forceLogin (keycloak, request, response) {
  let host = request.hostname;
  let headerHost = request.headers.host.split(':');
  let port = headerHost[1] || '';
  let protocol = request.protocol;
  let originalUrl = request.originalUrl || request.url;
  let queryIndex = originalUrl.indexOf('?');
  let pathname = queryIndex === -1 ? originalUrl : originalUrl.slice(0, queryIndex);
  let queryString = queryIndex === -1 ? '' : encodeUnsafeQueryChars(originalUrl.slice(queryIndex + 1));
  let hasQuery = queryIndex !== -1;

  let redirectUrl = protocol + '://' + host + (port === '' ? '' : ':' + port) + pathname + (hasQuery ? '?' + queryString + '&' : '?') + 'auth_callback=1';

  if (request.session) {
    request.session.auth_redirect_uri = redirectUrl;
  }

  let uuid = UUID();
  let loginURL = keycloak.loginUrl(uuid, redirectUrl);
  response.redirect(loginURL);
}

function simpleGuard (role, token) {
  return token.hasRole(role);
}

module.exports = function (keycloak, spec) {
  let guard;

  if (typeof spec === 'function') {
    guard = spec;
  } else if (typeof spec === 'string') {
    guard = simpleGuard.bind(undefined, spec);
  }

  return function protect (request, response, next) {
    if (request.kauth && request.kauth.grant) {
      if (!guard || guard(request.kauth.grant.access_token, request, response)) {
        return next();
      }

      return keycloak.accessDenied(request, response, next);
    }

    if (keycloak.redirectToLogin(request)) {
      forceLogin(keycloak, request, response);
    } else {
      return keycloak.accessDenied(request, response, next);
    }
  };
};
