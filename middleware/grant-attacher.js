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

const { SessionExpiredError } = require('./auth-utils/errors');
const { logoutAndRedirect } = require('./logout');

module.exports = function (keycloak) {
  return function grantAttacher (request, response, next) {
    keycloak.getGrant(request, response)
      .then(grant => {
        request.kauth.grant = grant;
      })
        .then(next).catch(err => {
        if (err instanceof SessionExpiredError) {
          // Session has reached maximum lifespan. A simple re-login redirect would loop because
          // Keycloak's SSO session is still alive. Perform a full RP-initiated logout first to
          // clear the Keycloak session, then the subsequent login redirect will work correctly.
          const isNavigational = !request.xhr && !!request.accepts('text/html');
          if (isNavigational) {
            if (err.grant && err.grant.unstore) {
              request.kauth.grant = err.grant;
            }
            return logoutAndRedirect(keycloak, request, response);
          }
        }

        // err can be undefined
          if (err) {
            console.error('Failed to get grant', err);
          }
          next();
        });
  };
};
