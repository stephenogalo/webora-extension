
"use strict";

const RESULT_PREFIX = "tab:";

function getBadge(result) {
  if (!result || typeof result.score !== "number") {
    return { text: "", color: "#64748b" };
  }

  if (result.level === "dangerous") {
    return { text: "!!", color: "#dc2626" };
  }

  if (result.level === "suspicious") {
    return { text: "!", color: "#d97706" };
  }

  return { text: "", color: "#16a34a" };
}

async function updateTabBadge(tabId, result) {
  const badge = getBadge(result);

  try {
    await chrome.action.setBadgeText({
      tabId,
      text: badge.text
    });

    await chrome.action.setBadgeBackgroundColor({
      tabId,
      color: badge.color
    });
  } catch (error) {
    console.debug("Webora: unable to update the tab badge.");
  }
}

async function saveTabResult(tabId, result) {
  try {
    await chrome.storage.session.set({
      [`${RESULT_PREFIX}${tabId}`]: result
    });
  } catch (error) {
    console.debug("Webora: unable to save the analysis result.");
  }
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type !== "WEBORA_ANALYSIS_RESULT") return;

  const tabId = sender.tab?.id;
  if (typeof tabId !== "number") return;

  const result = message.result;

  if (
    !result ||
    typeof result.score !== "number" ||
    !["safe", "suspicious", "dangerous"].includes(result.level)
  ) {
    return;
  }

  const safeResult = {
    score: Math.max(0, Math.min(100, result.score)),
    level: result.level,
    reasons: Array.isArray(result.reasons)
      ? result.reasons.filter(reason => typeof reason === "string").slice(0, 20)
      : [],
    trusted: result.trusted === true,
    host: typeof result.host === "string" ? result.host.slice(0, 253) : "",
    registrable: typeof result.registrable === "string"
      ? result.registrable.slice(0, 253)
      : ""
  };

  saveTabResult(tabId, safeResult);
  updateTabBadge(tabId, safeResult);
});

chrome.tabs.onRemoved.addListener(tabId => {
  try {
    chrome.storage.session.remove(`${RESULT_PREFIX}${tabId}`);
  } catch (error) {
    console.debug("Webora: unable to clear a closed tab's result.");
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "loading") return;

  try {
    chrome.storage.session.remove(`${RESULT_PREFIX}${tabId}`);
    chrome.action.setBadgeText({ tabId, text: "" });
  } catch (error) {
    console.debug("Webora: unable to reset a navigating tab.");
  }
});
