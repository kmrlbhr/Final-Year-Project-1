const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const { extractUrlFeatures, predictPhishingProbability, scoreUrlHeuristics } = require('../url_features.js');
require('../random_forest_model.js');
const model = globalThis.shieldPhishRandomForest;

const features = (url) => extractUrlFeatures(new URL(url));
const probability = (url) => predictPhishingProbability(model, features(url));

// Feature order matches FEATURE_NAMES in train_model.py; 1 = legitimate, -1 = phishing.
test('a short, plain URL is encoded as legitimate on every feature', () => {
  assert.deepEqual(features('https://example.com/'), [1, 1, 1, 1, 1, 1, 1]);
});

test('IP-address hosts are encoded as phishing', () => {
  assert.equal(features('http://192.168.10.5/login')[0], -1);
});

test('URL length uses the UCI 54 / 75 character bands', () => {
  assert.equal(features(`https://example.com/${'a'.repeat(20)}`)[1], 1);
  assert.equal(features(`https://example.com/${'a'.repeat(40)}`)[1], 0);
  assert.equal(features(`https://example.com/${'a'.repeat(70)}`)[1], -1);
});

test('URL shorteners are encoded as phishing, not legitimate', () => {
  assert.equal(features('https://bit.ly/3abcd')[2], -1);
  assert.equal(features('https://example.com/')[2], 1);
});

test('an @ in the URL is encoded as phishing, not legitimate', () => {
  assert.equal(features('https://example.com@evil.example/')[3], -1);
  assert.equal(features('https://example.com/')[3], 1);
});

test('extra // redirects, hyphenated hosts and deep subdomains are flagged', () => {
  assert.equal(features('https://example.com/redirect//evil.example')[4], -1);
  assert.equal(features('https://secure-login.example/')[5], -1);
  assert.equal(features('https://www.example.com/')[6], 0);
  assert.equal(features('https://a.b.example.com/')[6], -1);
  assert.equal(features('https://portal.unikl.edu.my/')[6], 0);
});

test('the model rates shortened and @ URLs as riskier than a plain URL', () => {
  const plain = probability('https://example.com/');
  assert.ok(probability('https://bit.ly/3abcd') > plain);
  assert.ok(probability('https://example.com@evil.example/') > plain);
});

test('the model returns a probability between 0 and 1', () => {
  for (const url of ['https://example.com/', 'http://192.168.10.5/a-b//c@d', 'https://a.b.c.secure-x.example/']) {
    const p = probability(url);
    assert.ok(p >= 0 && p <= 1, `${url} -> ${p}`);
  }
});

test('URL heuristics flag HTTP and scam-style hostnames', () => {
  assert.equal(scoreUrlHeuristics(new URL('https://example.com/')).score, 0);
  assert.equal(scoreUrlHeuristics(new URL('http://example.com/')).score, 20);
  assert.equal(scoreUrlHeuristics(new URL('https://verify-account.example/')).score, 18);
});

test('the manifest loads url_features.js after the model and before content.js', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  assert.deepEqual(manifest.content_scripts[0].js, ['random_forest_model.js', 'url_features.js', 'content.js']);
});

test('the extension never presents itself as another security brand', () => {
  for (const file of ['content.js', 'popup.html', 'popup.js', 'manifest.json']) {
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    assert.doesNotMatch(text, /mcafee|norton|kaspersky|avast|bitdefender|google safe browsing/i, file);
  }
});
