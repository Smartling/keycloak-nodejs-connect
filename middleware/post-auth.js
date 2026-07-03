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

const URL = require('url');

// Query parameters that Keycloak appends to the callback URL. They are not part
// of the redirect_uri that was sent on the authorization request, so they must
// be stripped when reconstructing it for the code-to-token exchange. Also used
// by `forceLogin` in protect.js to strip stale copies of these params from the
// current URL before it's captured as the redirect_uri for a fresh login.
const KEYCLOAK_CALLBACK_PARAMS = ['code', 'state', 'session_state', 'iss', 'error', 'error_description', 'error_uri'];

// Reconstruct the redirect_uri from the incoming callback URL rather than
// reading it from a single shared session key. The browser landed on this URL
// at exactly `redirect_uri` + the params Keycloak appended, so removing those
// params yields the exact redirect_uri that `forceLogin` originally sent (and
// that Keycloak requires to match byte-for-byte). Doing this per-request makes
// concurrent logins from multiple tabs safe - each callback resolves its own
// redirect_uri instead of clobbering a shared session value. See AUT-1461.
function reconstructRedirectUri (request) {
  const host = request.hostname;
  const headerHost = request.headers.host.split(':');
  const port = headerHost[1] || '';
  const protocol = request.protocol;
  const baseUrl = protocol + '://' + host + (port === '' ? '' : ':' + port);

  const originalUrl = request.originalUrl || request.url;
  const queryIndex = originalUrl.indexOf('?');
  const pathname = queryIndex === -1 ? originalUrl : originalUrl.slice(0, queryIndex);
  const queryString = queryIndex === -1 ? '' : originalUrl.slice(queryIndex + 1);

  // Filter by raw segments (no decode/re-encode) so the retained portion stays
  // byte-identical to what forceLogin built.
  const retained = queryString
    .split('&')
    .filter(segment => segment.length > 0)
    .filter(segment => KEYCLOAK_CALLBACK_PARAMS.indexOf(segment.split('=')[0]) === -1);

  return baseUrl + pathname + (retained.length ? '?' + retained.join('&') : '');
}

module.exports = function (keycloak) {
  return function postAuth (request, response, next) {
    if (!request.query.auth_callback) {
      return next();
    }

    if (request.query.error && !request.query.code) {
      return keycloak.accessDenied(request, response, next);
    }

    const redirectUri = reconstructRedirectUri(request);

    keycloak.getGrantFromCode(request.query.code, request, response, redirectUri)
      .then(grant => {
        let urlParts = {
          pathname: request.path,
          query: request.query
        };

        delete urlParts.query.auth_callback;
        KEYCLOAK_CALLBACK_PARAMS.forEach(param => delete urlParts.query[param]);

        let cleanUrl = URL.format(urlParts);

        request.kauth.grant = grant;
        try {
          keycloak.authenticated(request);
        } catch (err) {
          console.error(err);
        }
        response.redirect(cleanUrl);
      }).catch((err) => {
        keycloak.accessDenied(request, response);
        console.error('Could not obtain grant code: ' + err);
      });
  };
};

module.exports.KEYCLOAK_CALLBACK_PARAMS = KEYCLOAK_CALLBACK_PARAMS;
