// URL feature extraction and Random Forest inference shared by the content script,
// the tests and the evaluation script. Encodings follow the UCI Phishing Websites
// dataset: 1 = legitimate, 0 = suspicious, -1 = phishing.
(() => {
  const COMMON_SECOND_LEVEL_SUFFIXES = new Set([
    'co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'com.cn', 'co.in', 'com.my', 'edu.my', 'gov.my'
  ]);
  const SHORTENING_HOSTS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rebrand.ly'
  ];
  const SUSPICIOUS_HOST_PATTERNS = [
    'verify-', 'secure-', 'confirm-', 'account-security', 'password-reset',
    'update-password', 'payment-verify', 'fraud-protection', 'security-alert'
  ];

  function extractUrlFeatures(parsedUrl) {
    const hostname = parsedUrl.hostname.toLowerCase();
    const hostnameParts = hostname.split('.').filter(Boolean);
    const suffix = hostnameParts.slice(-2).join('.');
    const rootDomainParts = COMMON_SECOND_LEVEL_SUFFIXES.has(suffix) ? 3 : 2;
    const subdomainCount = Math.max(0, hostnameParts.length - rootDomainParts);
    const isShortened = SHORTENING_HOSTS.some((host) =>
      hostname === host || hostname.endsWith(`.${host}`)
    );

    return [
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) ? -1 : 1,
      parsedUrl.href.length < 54 ? 1 : parsedUrl.href.length < 75 ? 0 : -1,
      isShortened ? -1 : 1,
      parsedUrl.href.includes('@') ? -1 : 1,
      parsedUrl.href.indexOf('//', 7) > 7 ? -1 : 1,
      hostname.includes('-') ? -1 : 1,
      subdomainCount === 0 ? 1 : subdomainCount === 1 ? 0 : -1
    ];
  }

  function predictPhishingProbability(model, features) {
    if (!model?.trees?.length) {
      return null;
    }

    const probabilitySum = model.trees.reduce((sum, nodes) => {
      let node = nodes[0];
      while (node.left !== -1 && node.right !== -1) {
        node = nodes[features[node.feature] <= node.threshold ? node.left : node.right];
      }
      return sum + node.phishing;
    }, 0);

    return probabilitySum / model.trees.length;
  }

  // URL-only heuristics. Page-content heuristics stay in content.js because they need the DOM.
  // ignoreScheme is for datasets that store URLs without http:// or https://.
  function scoreUrlHeuristics(parsedUrl, { ignoreScheme = false } = {}) {
    const hostname = parsedUrl.hostname.toLowerCase();
    const reasons = [];
    let score = 0;

    if (!ignoreScheme && parsedUrl.protocol !== 'https:') {
      score += 20;
      reasons.push('Page is not using HTTPS');
    }

    if (SUSPICIOUS_HOST_PATTERNS.some((pattern) => hostname.includes(pattern))) {
      score += 18;
      reasons.push('URL has a scam-style hostname pattern');
    }

    if (hostname.includes('-') && hostname.split('.').length > 3) {
      score += 10;
      reasons.push('URL has layered host structure');
    }

    return { score, reasons };
  }

  const api = { extractUrlFeatures, predictPhishingProbability, scoreUrlHeuristics };
  globalThis.shieldPhishUrl = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})();
