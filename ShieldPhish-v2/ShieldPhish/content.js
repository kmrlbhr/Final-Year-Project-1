(() => {
  const randomForestModel = globalThis.shieldPhishRandomForest;
  const { extractUrlFeatures, predictPhishingProbability, scoreUrlHeuristics } = globalThis.shieldPhishUrl;
  const HIGH_RISK_THRESHOLD = 70;
  const MEDIUM_RISK_THRESHOLD = 45;

  // Constrain signals to scam-like phrases that are rarely used on normal business or social pages.
  const suspiciousTerms = [
    'account suspended',
    'verify your account',
    'update your password immediately',
    'confirm your identity',
    'claim your reward',
    'limited time offer',
    'urgent action required',
    'suspicious activity detected',
    'unusual login activity',
    'wire transfer required',
    'invoice payment required',
    'security action required',
    'your account has been restricted'
  ];

  function isHiddenFrame(frame) {
    const style = window.getComputedStyle(frame);
    return style.display === 'none'
      || style.visibility === 'hidden'
      || frame.offsetWidth <= 1
      || frame.offsetHeight <= 1;
  }

  function analyzePage() {
    const url = window.location.href;
    const reasons = [];
    let score = 0;

    let modelProbability = null;
    let isHttps = true;
    try {
      const parsed = new URL(url);
      isHttps = parsed.protocol === 'https:';
      modelProbability = predictPhishingProbability(randomForestModel, extractUrlFeatures(parsed));
      const urlResult = scoreUrlHeuristics(parsed);
      score += urlResult.score;
      reasons.push(...urlResult.reasons);
    } catch (error) {
      score += 10;
      reasons.push('URL format could not be fully parsed');
    }

    const titleText = document.title ? document.title.toLowerCase() : '';
    suspiciousTerms.forEach((term) => {
      if (titleText.includes(term)) {
        score += 12;
        reasons.push(`Title contains suspicious term: "${term}"`);
      }
    });

    const pageText = document.body ? document.body.innerText.toLowerCase() : '';
    suspiciousTerms.forEach((term) => {
      if (pageText.includes(term)) {
        score += 8;
        reasons.push(`Page text contains suspicious term: "${term}"`);
      }
    });

    // Anything flagged so far comes from the URL or the wording. A login form alone is normal
    // (banks, email, university portals), so it only weighs heavily alongside those signals.
    const hasOtherWarningSigns = score > 0 || (modelProbability ?? 0) >= 0.5;

    let credentialFieldCount = 0;
    document.querySelectorAll('input').forEach((input) => {
      const combined = `${input.name || ''} ${input.id || ''} ${input.type || ''}`.toLowerCase();
      if (/password|email|username|login|card|ssn/.test(combined)) {
        credentialFieldCount += 1;
      }
    });

    if (credentialFieldCount > 0) {
      if (hasOtherWarningSigns) {
        score += 12;
        reasons.push('Page asks for sensitive account or payment information');
        if (document.querySelector('form')) {
          score += 10;
          reasons.push('Credential collection form detected');
        }
      } else {
        score += 4;
        reasons.push('Page has a login or payment form');
      }
    }

    const passwordForms = [...document.querySelectorAll('form')]
      .filter((form) => form.querySelector('input[type="password"]'));
    const sendsElsewhere = passwordForms.some((form) => {
      try {
        const action = new URL(form.getAttribute('action') || '', window.location.href);
        return /^https?:$/.test(action.protocol) && action.hostname !== window.location.hostname;
      } catch {
        return false;
      }
    });
    if (sendsElsewhere) {
      score += 20;
      reasons.push('Login form sends your details to a different website');
    }

    if (!isHttps && document.querySelector('input[type="password"]')) {
      score += 15;
      reasons.push('Password field on a page without HTTPS');
    }

    const links = [...document.querySelectorAll('a[href]')];
    const externalLinks = links.filter((link) => {
      try {
        return new URL(link.href).hostname !== window.location.hostname;
      } catch {
        return false;
      }
    }).length;

    if (links.length > 0 && externalLinks / links.length > 0.5) {
      score += 8;
      reasons.push('Many links point to different domains');
    }

    if ([...document.querySelectorAll('iframe')].some(isHiddenFrame)) {
      score += 8;
      reasons.push('Hidden embedded content detected');
    }

    const heuristicScore = Math.min(score, 100);
    const modelPoints = modelProbability === null ? 0 : Math.round(modelProbability * 20);
    const normalizedScore = Math.min(100, heuristicScore + modelPoints);
    if (modelProbability !== null) {
      reasons.unshift(`Experimental Random Forest estimate: ${Math.round(modelProbability * 100)}% phishing likelihood`);
    }
    const uniqueReasons = [...new Set(reasons)];
    const verdict = normalizedScore >= HIGH_RISK_THRESHOLD
      ? 'High risk'
      : normalizedScore >= MEDIUM_RISK_THRESHOLD
        ? 'Medium risk'
        : 'Low risk';

    return {
      score: normalizedScore,
      verdict,
      modelProbability,
      reasons: uniqueReasons.length ? uniqueReasons : ['No strong phishing indicators detected']
    };
  }

  function showHighRiskWarning(result) {
    if (result.score < HIGH_RISK_THRESHOLD || document.getElementById('shieldphish-warning')) {
      return;
    }

    const host = document.createElement('div');
    host.id = 'shieldphish-warning';
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        .backdrop {
          position: fixed;
          inset: 0;
          z-index: 2147483647;
          display: grid;
          place-items: center;
          padding: 24px;
          box-sizing: border-box;
          background: rgba(11, 18, 26, 0.82);
          color: #15242d;
          font: 16px/1.5 system-ui, sans-serif;
          backdrop-filter: blur(2px);
        }
        .panel {
          width: min(100%, 540px);
          box-sizing: border-box;
          padding: 30px 30px 24px;
          border: 1px solid rgba(202, 200, 80, 0.35);
          border-top: 5px solid #f2b81f;
          background: linear-gradient(180deg, #f9fafb 0%, #edf1f4 100%);
          box-shadow: 0 22px 80px rgba(0, 0, 0, 0.42);
          border-radius: 10px;
        }
        .eyebrow {
          margin: 0 0 12px;
          color: #a41d18;
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 0.12em;
          text-transform: uppercase;
        }
        h1 {
          margin: 0;
          font-size: 30px;
          line-height: 1.15;
          color: #1a2a33;
          letter-spacing: -0.04em;
        }
        .summary { margin: 12px 0 20px; color: #42515a; }
        .score {
          display: inline-block;
          margin-bottom: 20px;
          padding: 7px 12px;
          background: #fff2c6;
          border: 1px solid #e7c864;
          color: #7d3d18;
          font-size: 14px;
          font-weight: 800;
          border-radius: 999px;
        }
        .signals { margin: 0 0 24px; padding-left: 20px; color: #2c3a42; }
        .signals li + li { margin-top: 6px; }
        .actions { display: flex; flex-wrap: wrap; gap: 10px; }
        button {
          min-height: 44px;
          padding: 10px 18px;
          border: 1px solid transparent;
          border-radius: 5px;
          cursor: pointer;
          font: inherit;
          font-weight: 700;
          transition: transform 0.15s ease, opacity 0.15s ease;
        }
        button:hover { transform: translateY(-1px); }
        button:focus-visible { outline: 3px solid #2d6f7a; outline-offset: 3px; }
        .leave {
          background: linear-gradient(180deg, #d95c46 0%, #b93d2f 100%);
          color: white;
          box-shadow: inset 0 1px 0 rgba(255,255,255,0.18);
        }
        .continue {
          border-color: #51636c;
          background: linear-gradient(180deg, #2f4650 0%, #21353d 100%);
          color: white;
        }
        .note { margin: 18px 0 0; color: #5d6d74; font-size: 13px; }
        @media (max-width: 480px) {
          .backdrop { padding: 14px; }
          .panel { padding: 24px 20px; }
          h1 { font-size: 24px; }
          .actions { flex-direction: column; }
          button { width: 100%; }
        }
      </style>
      <section class="backdrop" role="alertdialog" aria-modal="true" aria-labelledby="shieldphish-title" aria-describedby="shieldphish-summary">
        <div class="panel">
          <p class="eyebrow">ShieldPhish warning</p>
          <h1 id="shieldphish-title">This page looks suspicious</h1>
          <p class="summary" id="shieldphish-summary">We found several warning signs. This may be a false alarm, but avoid entering passwords or payment details unless you trust this site.</p>
          <div class="score">High risk · ${result.score}/100</div>
          <ul class="signals"></ul>
          <div class="actions">
            <button class="leave" type="button">Go back</button>
            <button class="continue" type="button">Continue anyway</button>
          </div>
          <p class="note">Your page is analyzed locally in this browser.</p>
        </div>
      </section>
    `;

    const signalList = shadow.querySelector('.signals');
    result.reasons.slice(0, 3).forEach((reason) => {
      const item = document.createElement('li');
      item.textContent = reason;
      signalList.append(item);
    });

    const [leaveButton, continueButton] = shadow.querySelectorAll('button');
    leaveButton.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.replace('about:blank');
      }
    });
    continueButton.addEventListener('click', () => host.remove());
    shadow.addEventListener('keydown', (event) => {
      if (event.key !== 'Tab') {
        return;
      }
      const activeButton = shadow.activeElement;
      if (event.shiftKey && activeButton === leaveButton) {
        event.preventDefault();
        continueButton.focus();
      } else if (!event.shiftKey && activeButton === continueButton) {
        event.preventDefault();
        leaveButton.focus();
      }
    });

    document.documentElement.append(host);
    leaveButton.focus();
  }

  function sendRiskReport() {
    const result = analyzePage();
    showHighRiskWarning(result);
    chrome.runtime.sendMessage({
      type: 'phishRisk',
      score: result.score,
      verdict: result.verdict,
      reasons: result.reasons
    });
  }

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'getPhishStatus') {
      const result = analyzePage();
      sendResponse(result);
    }
  });

  sendRiskReport();
})();
