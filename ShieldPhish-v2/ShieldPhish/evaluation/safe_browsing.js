// Google Safe Browsing Lookup API (v4) client used as the baseline in the evaluation.
const SAFE_BROWSING_BATCH = 500;
const THREAT_TYPES = ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];

// Google's official test pages. The Safe Browsing API always reports these as threats, so they
// show whether an API key and the comparison are working. https://testsafebrowsing.appspot.com/
const TEST_URLS = [
  { url: 'https://testsafebrowsing.appspot.com/s/phishing.html', expectedThreat: 'SOCIAL_ENGINEERING' },
  { url: 'https://testsafebrowsing.appspot.com/s/malware.html', expectedThreat: 'MALWARE' },
  { url: 'https://testsafebrowsing.appspot.com/s/unwanted.html', expectedThreat: 'UNWANTED_SOFTWARE' }
];

// Returns a Map of flagged URL -> threat type. URLs that are not flagged are left out.
async function lookupUrls(urls, apiKey) {
  const flagged = new Map();
  for (let start = 0; start < urls.length; start += SAFE_BROWSING_BATCH) {
    const batch = urls.slice(start, start + SAFE_BROWSING_BATCH);
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'shieldphish-fyp', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: THREAT_TYPES,
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: batch.map((url) => ({ url }))
          }
        })
      }
    );
    if (!response.ok) {
      throw new Error(`Safe Browsing returned HTTP ${response.status}: ${await response.text()}`);
    }
    const body = await response.json();
    (body.matches || []).forEach((match) => flagged.set(match.threat.url, match.threatType));
  }
  return flagged;
}

module.exports = { lookupUrls, TEST_URLS, THREAT_TYPES };
