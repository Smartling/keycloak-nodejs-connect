'use strict';

// Keycloak's default login theme field IDs. If Smartling's stg login theme
// (based on the KC1 template, see CLAUDE.md context) uses different IDs,
// repro.js's login step will fail with a Playwright timeout naming whichever
// selector below it couldn't find - update the values here to match.
module.exports = {
  username: '#username',
  password: '#password',
  submit: '#kc-login'
};
