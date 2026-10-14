const resultEl = document.getElementById('result');
const scoreEl = document.getElementById('score');
const urlEl = document.getElementById('url');
const reasonsEl = document.getElementById('reasons');
const scoreTrackEl = document.querySelector('.score-track span');
const assessmentCopyEl = document.querySelector('.assessment-copy');

function listItem(text) {
  const item = document.createElement('li');
  item.textContent = text;
  return item;
}

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function loadRisk() {
  const tab = await getCurrentTab();
  const url = tab?.url || 'about:blank';
  urlEl.textContent = url;

  chrome.tabs.sendMessage(tab.id, { type: 'getPhishStatus' }, (response) => {
    if (chrome.runtime.lastError || !response) {
      resultEl.textContent = 'Unable to scan';
      resultEl.className = 'status medium';
      scoreEl.textContent = '0';
      reasonsEl.replaceChildren(listItem('Try reloading the page.'));
      return;
    }

    const score = Math.max(0, Math.min(100, Number(response.score) || 0));
    scoreEl.textContent = String(score);
    scoreTrackEl.style.width = `${Math.max(score, 4)}%`;

    const highRiskThreshold = 70;
    const mediumRiskThreshold = 45;

    let className = 'low';
    let label = 'Low risk';
    if (score >= highRiskThreshold) {
      className = 'high';
      label = 'High risk';
    } else if (score >= mediumRiskThreshold) {
      className = 'medium';
      label = 'Medium risk';
    }

    resultEl.textContent = label;
    resultEl.className = `status ${className}`;
    assessmentCopyEl.textContent = score >= highRiskThreshold
      ? 'Multiple warning signs were found on this page.'
      : score >= mediumRiskThreshold
        ? 'A few signals need your attention before you continue.'
        : 'No strong phishing indicators were detected on this page.';

    const reasons = response.reasons || ['No suspicious signals found'];
    reasonsEl.replaceChildren(...reasons.slice(0, 5).map(listItem));
  });
}

loadRisk();
