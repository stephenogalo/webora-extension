
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.PhishDetector = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const TWO_PART_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.nz",
    "com.br", "co.jp", "co.in", "co.ke",
    "or.ke", "ac.ke", "go.ke", "sc.ke", "ne.ke"
  ]);

  const SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "top", "xyz", "click",
    "work", "country", "gq", "tk", "rest"
  ]);

  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "rb.gy", "shorturl.at"
  ]);

  const SUSPICIOUS_PATH_WORDS = new Set([
    "login", "log-in", "signin", "sign-in",
    "verify", "verification", "secure",
    "update", "account", "password", "authenticate"
  ]);

  const BRANDS = {
    paypal: ["paypal.com"],
    google: ["google.com", "google.co.ke"],
    microsoft: ["microsoft.com", "live.com", "outlook.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com", "amazon.co.uk"],
    facebook: ["facebook.com"],
    instagram: ["instagram.com"],
    whatsapp: ["whatsapp.com", "whatsapp.net"],
    netflix: ["netflix.com"],
    linkedin: ["linkedin.com"],
    github: ["github.com", "github.io"],
    dropbox: ["dropbox.com"],
    coinbase: ["coinbase.com"],
    binance: ["binance.com"],
    chase: ["chase.com"],
    wellsfargo: ["wellsfargo.com"],
    bankofamerica: ["bankofamerica.com"],
    safaricom: ["safaricom.co.ke"],
    mpesa: ["m-pesa.com", "mpesa.co.ke"]
  };

  function registrableDomain(host) {
    const hostname = String(host || "")
      .toLowerCase()
      .replace(/\.$/, "");

    const parts = hostname.split(".");

    if (
      !hostname ||
      hostname === "localhost" ||
      /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
      hostname.includes(":")
    ) {
      return hostname;
    }

    if (parts.length < 2) return hostname;

    const suffix = parts.slice(-2).join(".");
    const suffixLength = TWO_PART_SUFFIXES.has(suffix) ? 2 : 1;
    const index = parts.length - suffixLength - 1;

    return index >= 0 ? parts.slice(index).join(".") : hostname;
  }

  function levenshtein(a, b) {
    a = String(a);
    b = String(b);

    const previous = Array.from(
      { length: b.length + 1 },
      (_, i) => i
    );

    for (let i = 1; i <= a.length; i++) {
      let diagonal = previous[0];
      previous[0] = i;

      for (let j = 1; j <= b.length; j++) {
        const above = previous[j];
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;

        previous[j] = Math.min(
          previous[j] + 1,
          previous[j - 1] + 1,
          diagonal + cost
        );

        diagonal = above;
      }
    }

    return previous[b.length];
  }

  function deLeet(value) {
    const replacements = {
      "0": "o", "1": "l", "3": "e", "4": "a",
      "5": "s", "7": "t", "@": "a", "$": "s"
    };

    return String(value || "")
      .toLowerCase()
      .replace(/rn/g, "m")
      .replace(/[013457@$]/g, char => replacements[char]);
  }

  function getRecognizedBrand(host) {
    const domain = registrableDomain(host);

    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (domains.some(known =>
        domain === known || domain.endsWith(`.${known}`)
      )) {
        return brand;
      }
    }

    return null;
  }

  function getLevel(score) {
    if (score >= 55) return "dangerous";
    if (score >= 25) return "suspicious";
    return "safe";
  }

  function createResult({
    score = 0,
    reasons = [],
    trusted = false,
    host = "",
    registrable = ""
  } = {}) {
    const cappedScore = Math.max(0, Math.min(100, score));

    return {
      score: cappedScore,
      level: getLevel(cappedScore),
      reasons,
      trusted,
      host,
      registrable
    };
  }

  function analyzeUrl(input) {
    let url;

    try {
      url = new URL(input);
    } catch {
      return createResult({
        score: 100,
        reasons: ["The URL is invalid or could not be parsed."]
      });
    }

    const host = url.hostname.toLowerCase();
    const registrable = registrableDomain(host);

    if (!["http:", "https:"].includes(url.protocol)) {
      return createResult({
        score: 100,
        reasons: ["This URL does not use HTTP or HTTPS."],
        host,
        registrable
      });
    }

    const reasons = [];
    let score = 0;

    function addRisk(points, reason) {
      score += points;
      reasons.push(reason);
    }

    if (url.protocol !== "https:") {
      addRisk(15, "The website does not use HTTPS.");
    }

    if (url.username || url.password || url.href.includes("@")) {
      addRisk(25, "The URL contains an @ symbol or embedded credentials.");
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      addRisk(30, "The website uses a raw IPv4 address.");
    }

    if (host.split(".").some(label => label.startsWith("xn--"))) {
      addRisk(30, "The hostname contains a punycode label.");
    }

    const tld = host.split(".").pop();

    if (SUSPICIOUS_TLDS.has(tld)) {
      addRisk(12, `The hostname uses the potentially risky .${tld} domain ending.`);
    }

    if (SHORTENERS.has(registrable)) {
      addRisk(15, "The URL uses a known link-shortening service.");
    }

    if (url.href.length > 100) {
      addRisk(8, "The URL is unusually long.");
    }

    if ((host.match(/-/g) || []).length >= 3) {
      addRisk(10, "The hostname contains three or more hyphens.");
    }

    const subdomainCount = Math.max(
      0,
      host.split(".").length - registrable.split(".").length
    );

    if (subdomainCount >= 3) {
      addRisk(15, "The hostname contains several subdomain levels.");
    }

    const pathWords = url.pathname
      .toLowerCase()
      .split(/[^a-z0-9-]+/)
      .filter(Boolean);

    const suspiciousCount = new Set(
      pathWords.filter(word => SUSPICIOUS_PATH_WORDS.has(word))
    ).size;

    if (suspiciousCount >= 2) {
      addRisk(10, "The URL path contains multiple account or verification terms.");
    }

    // Flag a known brand domain embedded in a misleading hostname.
    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (domains.some(knownDomain => host.includes(`${knownDomain}.`))) {
        addRisk(
          25,
          `The hostname embeds a ${brand} domain inside an unrelated domain.`
        );
        break;
      }
    }

    const labels = registrable.split(/[.-]/).filter(Boolean);

    for (const [brand, domains] of Object.entries(BRANDS)) {
      const knownNames = new Set([
        brand,
        ...domains.map(domain => domain.split(".")[0])
      ]);

      const official = domains.some(domain =>
        registrable === domain || registrable.endsWith(`.${domain}`)
      );

      if (official) continue;

      if (labels.some(label => knownNames.has(label))) {
        addRisk(
          35,
          `The registered domain uses the ${brand} name on an unrecognized domain.`
        );
        break;
      }

      if (labels.some(label =>
        [...knownNames].some(name =>
          deLeet(label) === name && label !== name
        )
      )) {
        addRisk(
          55,
          `The registered domain may imitate the ${brand} brand using lookalike characters.`
        );
        break;
      }

      if (labels.some(label =>
        [...knownNames].some(name =>
          name.length >= 5 &&
          label.length >= 5 &&
          levenshtein(label, name) === 1
        )
      )) {
        addRisk(
          45,
          `The registered domain resembles the ${brand} name.`
        );
        break;
      }
    }

    return createResult({ score, reasons, host, registrable });
  }

  function analyzePage(page, baseUrl) {
    const urlResult = analyzeUrl(baseUrl);
    let score = urlResult.score;
    const reasons = [...urlResult.reasons];

    let pageUrl;

    try {
      pageUrl = new URL(baseUrl);
    } catch {
      return createResult({
        score: 100,
        reasons: ["The page URL is invalid or could not be parsed."]
      });
    }

    const pageDomain = registrableDomain(pageUrl.hostname);

    function addRisk(points, reason) {
      score += points;
      reasons.push(reason);
    }

    const forms = Array.isArray(page?.forms) ? page.forms.slice(0, 20) : [];
    const links = Array.isArray(page?.links) ? page.links.slice(0, 300) : [];
    const title = String(page?.title || "").slice(0, 300);
    const hasPassword = Boolean(page?.hasPasswordField);

    if (hasPassword && pageUrl.protocol !== "https:") {
      addRisk(25, "The page contains a password field but does not use HTTPS.");
    }

    for (const form of forms) {
      if (!form || !form.action) continue;

      try {
        const actionUrl = new URL(form.action, pageUrl);

        if (
          actionUrl.protocol === "http:" &&
          pageUrl.protocol === "https:"
        ) {
          addRisk(15, "A secure page submits a form over HTTP.");
          break;
        }

        if (
          hasPassword &&
          registrableDomain(actionUrl.hostname) !== pageDomain
        ) {
          addRisk(25, "A password form submits to a different registered domain.");
          break;
        }
      } catch {
        addRisk(10, "A form has an invalid submission destination.");
      }
    }

    if (hasPassword) {
      const titleLower = title.toLowerCase();

      for (const [brand, domains] of Object.entries(BRANDS)) {
        const titleMentionsBrand =
          titleLower.includes(brand) ||
          domains.some(domain =>
            titleLower.includes(domain.split(".")[0])
          );

        const isOfficial = domains.some(domain =>
          pageDomain === domain ||
          pageDomain.endsWith(`.${domain}`)
        );

        if (titleMentionsBrand && !isOfficial) {
          addRisk(
            30,
            `The page title mentions ${brand} and includes a password field on an unrelated domain.`
          );
          break;
        }
      }
    }

    for (const link of links) {
      if (!link || !link.href || !link.text) continue;

      const visibleText = String(link.text).trim();

      if (!/^(https?:\/\/|www\.)/i.test(visibleText)) continue;

      try {
        const displayedUrl = new URL(
          visibleText.startsWith("www.")
            ? `https://${visibleText}`
            : visibleText
        );

        const actualUrl = new URL(link.href, pageUrl);

        if (
          registrableDomain(displayedUrl.hostname) !==
          registrableDomain(actualUrl.hostname)
        ) {
          addRisk(
            25,
            "A link displays one website address but leads to another domain."
          );
          break;
        }
      } catch {
        // Ignore visible text that cannot be parsed as a URL.
      }
    }

    return createResult({
      score,
      reasons,
      host: urlResult.host,
      registrable: urlResult.registrable
    });
  }

  return {
    registrableDomain,
    levenshtein,
    deLeet,
    getRecognizedBrand,
    BRANDS,
    getLevel,
    createResult,
    analyzeUrl,
    analyzePage
  };
});
