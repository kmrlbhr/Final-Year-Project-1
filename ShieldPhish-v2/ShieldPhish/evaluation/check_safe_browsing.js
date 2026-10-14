// Checks the Google Safe Browsing baseline against Google's official test pages
// (https://testsafebrowsing.appspot.com/) and shows how ShieldPhish's URL score compares.
//
// Usage:
//   $env:GOOGLE_SAFE_BROWSING_API_KEY = "your-key"   (PowerShell)
//   node evaluation/check_safe_browsing.js
const { extractUrlFeatures, predictPhishingProbability, scoreUrlHeuristics } = require('../url_features.js');
require('../random_forest_model.js');
const { lookupUrls, TEST_URLS } = require('./safe_browsing.js');

const model = globalThis.shieldPhishRandomForest;
const URL_SCORE_THRESHOLD = 20;

function urlScore(url) {
  const parsed = new URL(url);
  const probability = predictPhishingProbability(model, extractUrlFeatures(parsed));
  return Math.min(100, scoreUrlHeuristics(parsed).score + Math.round(probability * 20));
}

async function runCheck(apiKey) {
  const flagged = await lookupUrls(TEST_URLS.map((test) => test.url), apiKey);
  return TEST_URLS.map((test) => {
    const score = urlScore(test.url);
    const threat = flagged.get(test.url) || null;
    return {
      ...test,
      safeBrowsingThreat: threat,
      safeBrowsingPassed: threat === test.expectedThreat,
      shieldPhishScore: score,
      shieldPhishFlagged: score >= URL_SCORE_THRESHOLD
    };
  });
}

async function main() {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    console.error('Set GOOGLE_SAFE_BROWSING_API_KEY first (see README, Evaluation).');
    process.exit(1);
  }
  const results = await runCheck(apiKey);
  console.log('Google Safe Browsing test pages\n');
  results.forEach((r) => {
    console.log(r.url);
    console.log(`  Safe Browsing: ${r.safeBrowsingThreat || 'not flagged'} (expected ${r.expectedThreat}) ${r.safeBrowsingPassed ? 'PASS' : 'FAIL'}`);
    console.log(`  ShieldPhish URL score: ${r.shieldPhishScore}/100 (${r.shieldPhishFlagged ? 'flagged' : 'not flagged'})`);
  });
  const passed = results.filter((r) => r.safeBrowsingPassed).length;
  console.log(`\nSafe Browsing matched ${passed} of ${results.length} test pages.`);
  console.log('These pages are on Google\'s blocklist but their URLs look ordinary, so ShieldPhish\'s URL '
    + 'checks are not expected to flag them. This shows the difference between a blocklist '
    + '(known pages only) and heuristics (suspicious-looking pages, including new ones).');
  process.exit(passed === results.length ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = { runCheck };
