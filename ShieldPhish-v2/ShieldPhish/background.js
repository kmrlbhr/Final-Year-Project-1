chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'phishRisk') {
    return;
  }

  const tabId = sender.tab?.id;
  const score = Math.min(Math.max(message.score || 0, 0), 100);

  const highRiskThreshold = 70;
  const mediumRiskThreshold = 45;

  let badgeText = '';
  let color = '#16a34a';

  if (score >= highRiskThreshold) {
    badgeText = '!';
    color = '#dc2626';
  } else if (score >= mediumRiskThreshold) {
    badgeText = '?';
    color = '#d97706';
  }

  if (tabId !== undefined) {
    chrome.action.setBadgeText({ tabId, text: badgeText });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  }

  sendResponse({ ok: true });
});
