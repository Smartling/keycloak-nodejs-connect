'use strict';

const readline = require('readline');

// Used to collect a live TOTP code at the moment of execution - these expire
// in ~30s, so they can never be stored in .env like the other credentials.
function promptLine (question) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(new Error(
        `Need to prompt for input ("${question}") but stdin isn't a TTY. ` +
        'Pass --totp=<code> on the command line instead when running non-interactively.'
      ));
      return;
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

module.exports = { promptLine };
