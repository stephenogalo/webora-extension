
const test = require("node:test");
const assert = require("node:assert/strict");

const detector = require("../src/detector.js");

test("flags a password field on HTTP", () => {
  const result = detector.analyzePage(
    {
      title: "Account login",
      hasPasswordField: true,
      forms: [],
      links: []
    },
    "http://example.com/login"
  );

  assert.ok(
    result.reasons.some(reason => reason.includes("password field"))
  );
  assert.ok(result.score >= 25);
});

test("flags a password form submitting to another domain", () => {
  const result = detector.analyzePage(
    {
      title: "Account login",
      hasPasswordField: true,
      forms: [{ action: "https://other.example.net/submit" }],
      links: []
    },
    "https://example.com/login"
  );

  assert.ok(
    result.reasons.some(reason => reason.includes("different registered domain"))
  );
});

test("flags a secure page submitting a form over HTTP", () => {
  const result = detector.analyzePage(
    {
      title: "Contact",
      hasPasswordField: false,
      forms: [{ action: "http://example.com/submit" }],
      links: []
    },
    "https://example.com/contact"
  );

  assert.ok(
    result.reasons.some(reason => reason.includes("submits a form over HTTP"))
  );
});

test("flags a misleading visible URL", () => {
  const result = detector.analyzePage(
    {
      title: "Offers",
      hasPasswordField: false,
      forms: [],
      links: [
        {
          text: "https://paypal.com",
          href: "https://example.net/collect"
        }
      ]
    },
    "https://example.com/"
  );

  assert.ok(
    result.reasons.some(reason => reason.includes("displays one website address"))
  );
});

test("does not treat ordinary link text as a displayed URL", () => {
  const result = detector.analyzePage(
    {
      title: "Offers",
      hasPasswordField: false,
      forms: [],
      links: [
        {
          text: "Read our guide to PayPal",
          href: "https://example.net/guide"
        }
      ]
    },
    "https://example.com/"
  );

  assert.equal(
    result.reasons.some(reason => reason.includes("displays one website address")),
    false
  );
});

