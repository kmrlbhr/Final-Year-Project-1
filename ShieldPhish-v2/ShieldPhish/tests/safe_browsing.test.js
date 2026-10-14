// Tests the Safe Browsing client with a simulated API, so no key or network is needed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { lookupUrls, TEST_URLS } = require('../evaluation/safe_browsing.js');
const { runCheck } = require('../evaluation/check_safe_browsing.js');

// Simulates the Lookup API: Google's test pages match, everything else does not.
function fakeSafeBrowsing(requests) {
  return async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, body });
    const known = new Map(TEST_URLS.map((t) => [t.url, t.expectedThreat]));
    const matches = body.threatInfo.threatEntries
      .filter((entry) => known.has(entry.url))
      .map((entry) => ({ threatType: known.get(entry.url), threat: { url: entry.url } }));
    return { ok: true, json: async () => (matches.length ? { matches } : {}) };
  };
}

test('test pages are reported with their threat type and other URLs are not', async (t) => {
  const requests = [];
  t.mock.method(globalThis, 'fetch', fakeSafeBrowsing(requests));
  const flagged = await lookupUrls([...TEST_URLS.map((x) => x.url), 'https://example.com/'], 'test-key');
  assert.equal(flagged.get('https://testsafebrowsing.appspot.com/s/phishing.html'), 'SOCIAL_ENGINEERING');
  assert.equal(flagged.get('https://testsafebrowsing.appspot.com/s/malware.html'), 'MALWARE');
  assert.equal(flagged.has('https://example.com/'), false);
  assert.match(requests[0].url, /threatMatches:find\?key=test-key$/);
});

test('large URL lists are sent in batches of 500', async (t) => {
  const requests = [];
  t.mock.method(globalThis, 'fetch', fakeSafeBrowsing(requests));
  const urls = Array.from({ length: 1201 }, (_, i) => `https://site${i}.example/`);
  await lookupUrls(urls, 'test-key');
  assert.deepEqual(requests.map((r) => r.body.threatInfo.threatEntries.length), [500, 500, 201]);
});

test('an API error is reported instead of silently counting URLs as safe', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => ({ ok: false, status: 400, text: async () => 'API key not valid' }));
  await assert.rejects(lookupUrls(['https://example.com/'], 'bad-key'), /HTTP 400: API key not valid/);
});

test('the self-check passes when Safe Browsing flags every test page', async (t) => {
  t.mock.method(globalThis, 'fetch', fakeSafeBrowsing([]));
  const results = await runCheck('test-key');
  assert.equal(results.length, 3);
  assert.ok(results.every((r) => r.safeBrowsingPassed));
  // The test pages have ordinary URLs, so ShieldPhish's URL checks leave them alone.
  assert.ok(results.every((r) => !r.shieldPhishFlagged));
});
