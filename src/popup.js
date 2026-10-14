
"use strict";

const levelElement = document.getElementById("level");
const hostElement = document.getElementById("host");
const scoreElement = document.getElementById("score");
const reasonsElement = document.getElementById("reasons");
const meterElement = document.getElementById("meter");
const meterFill = document.getElementById("meter-fill");
const noticeElement = document.getElementById("notice");
const statusElement = document.getElementById("status");

function showMessage(title, message) {
  levelElement.textContent = title;
  hostElement.textContent = "";
  scoreElement.textContent = "—/100";
  reasonsElement.replaceChildren();

  const item = document.createElement("li");
  item.textContent = message;
  reasonsElement.appendChild(item);

  noticeElement.textContent = "";
  meterFill.style.width = "0%";
  meterElement.setAttribute("aria-valuenow", "0");
}

function displayResult(result) {
  if (!result || typeof result.score !== "number") {
    showMessage(
      "No result available",
      "Reload the website and open Webora again."
    );
    return;
  }

  const score = Math.max(0, Math.min(100, result.score));
  const level = ["safe", "suspicious", "dangerous"].includes(result.level)
    ? result.level
    : "safe";

  const labels = {
    safe: "No major risks detected",
    suspicious: "Suspicious website",
    dangerous: "Potentially dangerous"
  };

  const colors = {
    safe: "#16a34a",
    suspicious: "#d97706",
    dangerous: "#dc2626"
  };

  levelElement.textContent = labels[level];
  hostElement.textContent = result.host || "Unknown website";
  scoreElement.textContent = `${score}/100`;

  meterFill.style.width = `${score}%`;
  meterFill.style.background = colors[level];
  meterElement.setAttribute("aria-valuenow", String(score));

  statusElement.style.borderColor = colors[level];

  reasonsElement.replaceChildren();

  const reasons = Array.isArray(result.reasons)
    ? result.reasons.filter(reason => typeof reason === "string").slice(0, 20)
    : [];

  if (reasons.length === 0) {
    const item = document.createElement("li");
    item.textContent = result.trusted
      ? "You have marked this domain as trusted."
      : "No major warning signals were detected.";
    reasonsElement.appendChild(item);
  } else {
    for (const reason of reasons) {
      const item = document.createElement("li");
      item.textContent = reason;
      reasonsElement.appendChild(item);
    }
  }

  noticeElement.textContent = result.trusted
    ? "This domain is on your trusted list. Trust does not guarantee safety."
    : "Automated checks can make mistakes. Stay alert.";
}

async function loadCurrentTabResult() {
  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    const tab = tabs[0];

    if (!tab || !tab.id || !tab.url) {
      showMessage("No active tab", "Open a website and try again.");
      return;
    }

    if (!/^https?:\/\//i.test(tab.url)) {
      showMessage(
        "Page cannot be inspected",
        "Browser-internal pages and some protected pages cannot be analyzed."
      );
      return;
    }

    const key = `tab:${tab.id}`;
    const stored = await chrome.storage.session.get(key);
    const result = stored[key];

    if (!result) {
      showMessage(
        "Waiting for analysis",
        "Reload the website, wait a moment, then open Webora again."
      );
      return;
    }

    displayResult(result);
  } catch {
    showMessage(
      "Could not load results",
      "Try reloading the page and opening Webora again."
    );
  }
}

loadCurrentTabResult();
