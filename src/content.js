
(() => {
  "use strict";

  if (window.__weboraContentLoaded) return;
  window.__weboraContentLoaded = true;

  const MAX_FORMS = 20;
  const MAX_LINKS = 300;
  const BANNER_ID = "webora-warning-host";

  let observer = null;
  let scanCount = 0;
  let scanTimer = null;

  function getPageSnapshot() {
    const forms = Array.from(document.forms)
      .slice(0, MAX_FORMS)
      .map(form => ({
        action: form.getAttribute("action") || window.location.href,
        method: (form.getAttribute("method") || "get").toLowerCase()
      }));

    const links = Array.from(document.links)
      .slice(0, MAX_LINKS)
      .map(link => ({
        href: link.href,
        text: (link.innerText || link.textContent || "")
          .trim()
          .slice(0, 300)
      }));

    return {
      title: document.title.slice(0, 300),
      hasPasswordField: Boolean(
        document.querySelector('input[type="password"]')
      ),
      forms,
      links
    };
  }

  function sendResult(result) {
    try {
      chrome.runtime.sendMessage(
        { type: "WEBORA_ANALYSIS_RESULT", result },
        () => {
          if (chrome.runtime.lastError) {
            console.debug("Webora: result could not be sent.");
          }
        }
      );
    } catch {
      console.debug("Webora: messaging is unavailable.");
    }
  }

  function showWarning(result) {
    const existing = document.getElementById(BANNER_ID);

    if (!result || result.level === "safe" || result.trusted) {
      existing?.remove();
      return;
    }

    if (existing) existing.remove();

    const host = document.createElement("div");
    host.id = BANNER_ID;

    // Keep the warning's internal DOM isolated from page styles and scripts.
    const shadow = host.attachShadow({ mode: "closed" });

    const banner = document.createElement("section");
    banner.setAttribute("role", "alert");
    banner.setAttribute("aria-live", "assertive");

    Object.assign(banner.style, {
      position: "fixed",
      top: "12px",
      right: "12px",
      width: "min(380px, calc(100vw - 24px))",
      maxHeight: "80vh",
      overflowY: "auto",
      boxSizing: "border-box",
      padding: "16px",
      borderRadius: "12px",
      color: "#ffffff",
      background: result.level === "dangerous" ? "#991b1b" : "#92400e",
      boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
      font: "14px/1.5 system-ui, sans-serif",
      zIndex: "2147483647"
    });

    const heading = document.createElement("h2");
    heading.textContent = result.level === "dangerous"
      ? "Webora: Potentially dangerous website"
      : "Webora: Suspicious website";

    Object.assign(heading.style, {
      margin: "0 0 8px",
      fontSize: "17px",
      lineHeight: "1.35"
    });

    const score = document.createElement("p");
    score.textContent = `Risk score: ${result.score}/100`;
    score.style.margin = "0 0 8px";

    const hostText = document.createElement("p");
    hostText.textContent = `Website: ${result.host || location.hostname}`;
    hostText.style.overflowWrap = "anywhere";
    hostText.style.margin = "0 0 8px";

    const reasonsList = document.createElement("ul");
    Object.assign(reasonsList.style, {
      paddingLeft: "20px",
      margin: "0 0 14px"
    });

    const reasons = Array.isArray(result.reasons)
      ? result.reasons.slice(0, 8)
      : [];

    for (const reason of reasons) {
      const item = document.createElement("li");
      item.textContent = String(reason);
      item.style.marginBottom = "4px";
      reasonsList.appendChild(item);
    }

    const buttons = document.createElement("div");
    Object.assign(buttons.style, {
      display: "flex",
      flexWrap: "wrap",
      gap: "8px"
    });

    function makeButton(label) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;

      Object.assign(button.style, {
        border: "1px solid rgba(255,255,255,0.7)",
        borderRadius: "7px",
        padding: "8px 10px",
        color: "#ffffff",
        background: "rgba(0,0,0,0.2)",
        font: "inherit",
        cursor: "pointer"
      });

      return button;
    }

    const dismissButton = makeButton("Dismiss");
    dismissButton.addEventListener("click", () => {
      host.remove();
    });

    const trustButton = makeButton("Trust this site");
    trustButton.addEventListener("click", async () => {
      const hostname = location.hostname.toLowerCase();

      try {
        const settings = await chrome.storage.sync.get({
          trustedDomains: []
        });

        const trustedDomains = Array.isArray(settings.trustedDomains)
          ? settings.trustedDomains.filter(value => typeof value === "string")
          : [];

        if (!trustedDomains.includes(hostname)) {
          trustedDomains.push(hostname);
        }

        await chrome.storage.sync.set({ trustedDomains });

        host.remove();

        sendResult({
          score: 0,
          level: "safe",
          reasons: ["You have marked this domain as trusted."],
          trusted: true,
          host: hostname,
          registrable: window.PhishDetector.registrableDomain(hostname)
        });
      } catch {
        trustButton.textContent = "Could not save trust setting";
        trustButton.disabled = true;
      }
    });

    buttons.append(dismissButton, trustButton);
    banner.append(heading, score, hostText, reasonsList, buttons);
    shadow.appendChild(banner);

    (document.body || document.documentElement).appendChild(host);
  }

  function analyzeCurrentPage() {
    try {
      if (!window.PhishDetector) return;

      const result = window.PhishDetector.analyzePage(
        getPageSnapshot(),
        window.location.href
      );

      sendResult(result);
      showWarning(result);
    } catch {
      console.debug("Webora: page analysis could not be completed.");
    }
  }

  function loadTrustedDomainsAndAnalyze() {
    try {
      chrome.storage.sync.get({ trustedDomains: [] }, settings => {
        if (chrome.runtime.lastError) {
          analyzeCurrentPage();
          return;
        }

        const trustedDomains = Array.isArray(settings.trustedDomains)
          ? settings.trustedDomains
          : [];

        const hostname = location.hostname.toLowerCase();

        const trusted = trustedDomains.some(domain => {
          if (typeof domain !== "string") return false;
          const normalized = domain.toLowerCase().trim();

          return hostname === normalized ||
            hostname.endsWith(`.${normalized}`);
        });

        if (trusted) {
          sendResult({
            score: 0,
            level: "safe",
            reasons: ["You have marked this domain as trusted."],
            trusted: true,
            host: hostname,
            registrable: window.PhishDetector
              ? window.PhishDetector.registrableDomain(hostname)
              : hostname
          });
          return;
        }

        analyzeCurrentPage();
      });
    } catch {
      analyzeCurrentPage();
    }
  }

  function startObserver() {
    if (!document.documentElement || observer) return;

    observer = new MutationObserver(() => {
      if (scanCount >= 5) return;

      clearTimeout(scanTimer);
      scanTimer = setTimeout(() => {
        scanCount += 1;
        analyzeCurrentPage();
      }, 700);
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  loadTrustedDomainsAndAnalyze();
  startObserver();
})();
