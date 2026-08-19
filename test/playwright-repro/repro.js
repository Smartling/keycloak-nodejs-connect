#!/usr/bin/env node
'use strict';

// Drives real Chromium against the stg fixture app, looping login -> wait
// past the session-cap window -> reload, trying to trigger the intermittent
// "Too Many Redirects" loop (AUT-1462). Plain script, not @playwright/test -
// this is a repeated-fuzz-style probe where "the bug happened" is the
// interesting outcome, not a pass/fail assertion. See README.md.

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { requireEnv, assertStgTarget } = require('./lib/env');
const { spawnFixtureApp } = require('./lib/spawn-fixture-app');
const selectors = require('./lib/login-selectors');

const RESULTS_DIR = path.join(__dirname, 'results');
const RESULTS_FILE = path.join(RESULTS_DIR, 'results.json');
const TRACES_DIR = path.join(RESULTS_DIR, 'traces');
const HAR_DIR = path.join(RESULTS_DIR, 'har');

// Mirrors the deep-linked URL shape from the real bug reports
// (/app/<accountId>?locale=fr&start=0&...) that the 14fb4ee fix targets.
const DEEP_LINK_PATH = '/app/playwright-repro-account?locale=fr&start=0&contentAuthorization=ALL';

function parseArgs (argv) {
  const args = { iterations: 20, tabs: 1, headed: false };
  for (const arg of argv) {
    if (arg === '--headed') {
      args.headed = true;
    } else if (arg.startsWith('--iterations=')) {
      args.iterations = Number(arg.split('=')[1]);
    } else if (arg.startsWith('--tabs=')) {
      args.tabs = Number(arg.split('=')[1]);
    } else {
      throw new Error(`Unrecognized argument: ${arg}`);
    }
  }
  if (![1, 2].includes(args.tabs)) {
    throw new Error('--tabs must be 1 or 2');
  }
  if (!Number.isInteger(args.iterations) || args.iterations < 1) {
    throw new Error('--iterations must be a positive integer');
  }
  return args;
}

function ensureDirs () {
  for (const dir of [RESULTS_DIR, TRACES_DIR, HAR_DIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function appendResult (row) {
  fs.appendFileSync(RESULTS_FILE, JSON.stringify(row) + '\n');
}

function sleep (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Tracks the navigation-only request chain for a page, reset before each
// reload attempt so counts reflect just that attempt, not the whole session.
function trackChain (page) {
  const state = { requests: [] };
  page.on('request', (request) => {
    if (request.isNavigationRequest()) {
      state.requests.push({ url: request.url(), method: request.method() });
    }
  });
  return state;
}

function resetChain (state) {
  state.requests.length = 0;
}

// Smartling's stg login theme is a two-step identifier-first flow (confirmed
// by live inspection, not assumed): the email field is submitted first via
// #kc-login, which reveals the password field (also submitted via the same
// #kc-login selector) rather than a single page with both fields at once.
// The submit button stays disabled (class stays "btn disabled") after a
// plain .fill() until the field is blurred - a Tab press is required after
// each fill before the button becomes clickable, also confirmed live.
async function login (page, baseUrl, env) {
  await page.goto(`${baseUrl}${DEEP_LINK_PATH}`, { waitUntil: 'domcontentloaded', timeout: 30000 });

  await page.waitForSelector(selectors.username, { timeout: 15000 });
  await page.fill(selectors.username, env.kcTestUsername);
  await page.press(selectors.username, 'Tab');
  await page.click(selectors.submit);

  await page.waitForSelector(selectors.password, { state: 'visible', timeout: 15000 });
  await page.fill(selectors.password, env.kcTestPassword);
  await page.press(selectors.password, 'Tab');
  await Promise.all([
    page.waitForURL(new RegExp(`^${escapeRegExp(baseUrl)}`), { timeout: 30000 }),
    page.click(selectors.submit)
  ]);
}

// Attempts the navigation that's expected to cross the session-cap boundary.
// Resolves with reproduced=true specifically when Chromium's own redirect
// cap fires (net::ERR_TOO_MANY_REDIRECTS) - the definitive "this is the bug"
// signal - rather than any navigation failure.
async function attemptReload (page, baseUrl) {
  try {
    await page.goto(`${baseUrl}${DEEP_LINK_PATH}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
    return { reproduced: false, error: null };
  } catch (err) {
    const message = err.message || String(err);
    return { reproduced: message.includes('ERR_TOO_MANY_REDIRECTS'), error: message };
  }
}

async function runIteration (browser, baseUrl, env, args, iteration) {
  const harPath = path.join(HAR_DIR, `iteration-${iteration}.har`);
  const context = await browser.newContext({ recordHar: { path: harPath } });
  await context.tracing.start({ screenshots: true, snapshots: true });

  const startedAt = Date.now();
  let reproduced = false;
  let errorMessage = null;
  const chains = [];

  try {
    const page1 = await context.newPage();
    chains.push(trackChain(page1));
    await login(page1, baseUrl, env);

    let page2 = null;
    if (args.tabs === 2) {
      page2 = await context.newPage();
      chains.push(trackChain(page2));
      await page2.goto(`${baseUrl}${DEEP_LINK_PATH}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
    }

    // The session-cap window (ensureFreshness() in grant-manager.js) only
    // exists for the last tokenMinTtlSeconds of the session - before that,
    // refreshes are normal; after the session fully ends, the refresh token
    // itself expires and a DIFFERENT, uninteresting error fires instead
    // ("Unable to refresh with expired refresh token", confirmed live).
    // A single fixed-delay reload easily overshoots that narrow window, so
    // instead: wait until just before it opens, then poll with reloads
    // through it and a bit past session end.
    const pollStartMs = Math.max(0, env.clientSessionMaxSeconds - env.tokenMinTtlSeconds - 3) * 1000;
    await sleep(pollStartMs);

    const pollEndAt = Date.now() + (env.tokenMinTtlSeconds + 15) * 1000;
    while (Date.now() < pollEndAt) {
      chains.forEach(resetChain);

      const reloadPromises = [attemptReload(page1, baseUrl)];
      if (page2) {
        reloadPromises.push(attemptReload(page2, baseUrl));
      }
      const results = await Promise.all(reloadPromises);

      reproduced = results.some((result) => result.reproduced);
      errorMessage = results.map((result) => result.error).filter(Boolean).join(' | ') || null;
      if (reproduced) {
        break;
      }
      await sleep(2000);
    }
  } catch (err) {
    errorMessage = err.message || String(err);
  }

  const elapsedMs = Date.now() - startedAt;

  await context.tracing.stop({ path: reproduced ? path.join(TRACES_DIR, `iteration-${iteration}.zip`) : undefined });
  await context.close(); // finalizes the HAR file

  if (!reproduced) {
    fs.rmSync(harPath, { force: true });
  }

  return {
    timestamp: new Date().toISOString(),
    iteration,
    tabs: args.tabs,
    clientSessionMaxSeconds: env.clientSessionMaxSeconds,
    tokenMinTtlSeconds: env.tokenMinTtlSeconds,
    reproduced,
    chainLengths: chains.map((chain) => chain.requests.length),
    elapsedMs,
    error: errorMessage
  };
}

async function main () {
  const args = parseArgs(process.argv.slice(2));
  const env = requireEnv();
  assertStgTarget(env);
  if (!env.kcClientSecret) {
    throw new Error('KC_CLIENT_SECRET is not set in .env - run `npm run provision:apply` first to create the client and fetch its secret.');
  }
  ensureDirs();

  console.log(`Spawning fixture app (Node 16) on port ${env.fixtureAppPort}...`);
  const fixtureApp = await spawnFixtureApp(env);
  const baseUrl = `http://localhost:${env.fixtureAppPort}`;

  // Real Chrome, not Playwright's bundled Chromium - matches what users
  // actually hit the bug in (per the original report: "intermittent website
  // issue... in Chrome"), and avoids a separate browser binary download when
  // Chrome is already installed.
  const browser = await chromium.launch({ channel: 'chrome', headless: !args.headed });

  let reproducedCount = 0;
  try {
    for (let iteration = 1; iteration <= args.iterations; iteration++) {
      const row = await runIteration(browser, baseUrl, env, args, iteration);
      appendResult(row);
      if (row.reproduced) {
        reproducedCount++;
      }
      console.log(
        `[iteration ${iteration}/${args.iterations}] reproduced=${row.reproduced} ` +
        `elapsedMs=${row.elapsedMs} chainLengths=${JSON.stringify(row.chainLengths)}`
      );
    }
  } finally {
    await browser.close();
    fixtureApp.stop();
  }

  console.log(`\nDone: ${reproducedCount}/${args.iterations} iterations reproduced the loop.`);
  console.log(`Results: ${RESULTS_FILE}`);
  if (reproducedCount > 0) {
    console.log(`Traces/HARs for reproducing iterations: ${TRACES_DIR}, ${HAR_DIR}`);
  }
}

main().catch((err) => {
  console.error('repro.js failed:', err.message || err);
  process.exit(1);
});
