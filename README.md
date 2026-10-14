# Webora — Web Protection Extension

**Browse freely. Stay protected.**

Webora is a lightweight browser extension that analyzes website URLs and selected page signals locally to identify potential phishing attempts, deceptive domains, and other suspicious browsing activity.

## Features

- **URL risk analysis:** Examines website addresses for suspicious patterns.
- **Lookalike-domain detection:** Checks for possible impersonation of recognised brands.
- **Page security checks:** Identifies selected warning signs, such as password fields on HTTP pages and forms submitting to another domain.
- **Risk scoring:** Classifies analysed pages as safe, suspicious, or dangerous.
- **Warning banner:** Displays a warning on pages classified as suspicious or dangerous.
- **Extension popup:** Displays the available analysis result, score, and reasons.
- **Local analysis:** Performs its detection checks in the browser without requiring a remote analysis server.
- **Trusted sites:** Allows users to mark a website as trusted.

## Technology

- JavaScript (ES2020)
- HTML and CSS
- Chrome Extensions Manifest V3
- Node.js test runner
- Chrome extension APIs

## Project Structure

```text
webora-extension/
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   └── webora.svg
├── src/
│   ├── background.js
│   ├── content.js
│   ├── detector.js
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── tests/
├── manifest.json
├── package.json
├── LICENSE
└── README.md
```

## Installation

1. Clone or download this repository.
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose the `webora-extension` project folder.
6. Open a website and select the Webora icon to view the available analysis result.

No paid developer registration is required to load the extension locally for development and testing.

## Running Tests

Install Node.js and npm if they are not already available. From the project directory, run:

```bash
npm test
```

The tests cover URL helper functions, recognised brand domains, lookalike detection, and selected page-security signals.

## Risk Classification

Webora uses a heuristic score to classify the signals it detects:

| Score | Classification |
|---|---|
| 0–24 | Safe |
| 25–54 | Suspicious |
| 55–100 | Dangerous |

A safe result does not guarantee that a website is legitimate. Likewise, a suspicious result is a warning to investigate rather than proof of malicious intent.

## Limitations

- Detection is based on implemented heuristics, not a guarantee of protection.
-I,ll say  I started from here ##26/14
