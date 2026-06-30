'use strict';

class SessionExpiredError extends Error {
  constructor (grant) {
    super('Session near maximum lifespan: re-login required');
    this.name = 'SessionExpiredError';
    this.grant = grant;
    this.idTokenHint = grant && grant.id_token && grant.id_token.token;
  }
}

module.exports = { SessionExpiredError };
