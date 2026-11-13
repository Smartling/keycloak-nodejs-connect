'use strict';

const path = require('path');
const fs = require('fs');
const { spawn, execSync } = require('child_process');

const FIXTURE_APP_PATH = path.join(__dirname, '..', 'fixture-app', 'app.js');
const READY_MARKER = 'FIXTURE_APP_READY';
const READY_TIMEOUT_MS = 20000;

// The fixture app requires this repo's own index.js/middleware, which need
// the root repo's node_modules to have been installed under Node 16 (see
// CLAUDE.md / .nvmrc - some root devDependencies only compile there). The
// Playwright driver itself runs under a newer Node (see package.json
// engines), so the two are spawned as separate processes on purpose - don't
// try to unify them.
function resolveNodeBinary (env) {
  if (env.fixtureNodeBinary) {
    if (!fs.existsSync(env.fixtureNodeBinary)) {
      throw new Error(
        `FIXTURE_NODE_BINARY is set to "${env.fixtureNodeBinary}" but that path does not exist.`
      );
    }
    return env.fixtureNodeBinary;
  }

  try {
    const resolved = execSync(
      'bash -lc \'source "$HOME/.nvm/nvm.sh" 2>/dev/null; nvm which 16\'',
      { encoding: 'utf8' }
    ).trim().split('\n').pop().trim();

    if (resolved && fs.existsSync(resolved)) {
      return resolved;
    }
  } catch (err) {
    // fall through to the actionable error below
  }

  throw new Error(
    'Could not find a Node 16 binary to run the fixture app.\n' +
    'Either run `nvm install 16` so `nvm which 16` resolves, or set ' +
    'FIXTURE_NODE_BINARY in .env to an absolute path to a Node 16 binary.'
  );
}

// Spawns the fixture app and resolves once it has printed its ready marker,
// or rejects (with the app's stderr attached) if it exits or times out first.
function spawnFixtureApp (env) {
  const nodeBinary = resolveNodeBinary(env);

  const child = spawn(nodeBinary, [FIXTURE_APP_PATH], {
    env: {
      ...process.env,
      KC_BASE_URL: env.kcBaseUrl,
      KC_REALM: env.kcRealm,
      KC_CLIENT_ID: env.kcClientId,
      KC_CLIENT_SECRET: env.kcClientSecret,
      FIXTURE_APP_PORT: String(env.fixtureAppPort),
      KC_TOKEN_MIN_TTL_SECONDS: String(env.tokenMinTtlSeconds)
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let stderrBuffer = '';
  child.stderr.on('data', (chunk) => {
    stderrBuffer += chunk.toString();
    process.stderr.write(`[fixture-app] ${chunk}`);
  });

  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(
        `Fixture app did not report ready within ${READY_TIMEOUT_MS}ms.\n` +
        `stderr so far:\n${stderrBuffer}`
      ));
    }, READY_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      process.stdout.write(`[fixture-app] ${text}`);
      if (text.includes(READY_MARKER)) {
        clearTimeout(timer);
        resolve();
      }
    });

    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Fixture app exited early (code ${code}) before becoming ready.\nstderr:\n${stderrBuffer}`));
    });
  });

  return ready.then(() => ({
    child,
    stop () {
      child.kill('SIGTERM');
    }
  }));
}

module.exports = { spawnFixtureApp, resolveNodeBinary };
