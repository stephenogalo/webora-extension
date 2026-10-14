const test = require("node:test");
const assert = require("node:assert/strict");

const detector = require("../src/detector.js");

test("registrableDomain handles common domains", () => {
  assert.equal(
    detector.registrableDomain("shop.example.com"),
    "example.com"
  );

  assert.equal(
    detector.registrableDomain("login.example.co.ke"),
    "example.co.ke"
  );

  assert.equal(
    detector.registrableDomain("secure.example.co.uk"),
    "example.co.uk"
  );
});

test("registrableDomain handles edge cases", () => {
  assert.equal(
    detector.registrableDomain("localhost"),
    "localhost"
  );

  assert.equal(
    detector.registrableDomain("127.0.0.1"),
    "127.0.0.1"
  );

  assert.equal(
    detector.registrableDomain("EXAMPLE.COM."),
    "example.com"
  );
});

test("levenshtein calculates edit distance", () => {
  assert.equal(detector.levenshtein("google", "google"), 0);
  assert.equal(detector.levenshtein("google", "goggle"), 1);
  assert.equal(detector.levenshtein("paypal", "paypa1"), 1);
  assert.equal(detector.levenshtein("cat", "dog"), 3);
  assert.equal(detector.levenshtein("", "abc"), 3);
});

test("deLeet normalizes common lookalike characters", () => {
  assert.equal(detector.deLeet("paypa1"), "paypal");
  assert.equal(detector.deLeet("g00gle"), "google");
  assert.equal(detector.deLeet("rnicrosoft"), "microsoft");
  assert.equal(detector.deLeet("h@ck3r"), "hacker");
});

test("analyzeUrl uses the registrable domain helper", () => {
  const result = detector.analyzeUrl(
    "https://login.example.co.ke/account"
  );

  assert.equal(result.host, "login.example.co.ke");
  assert.equal(result.registrable, "example.co.ke");
});

test("recognizes known brand domains and subdomains", () => {
  assert.equal(
    detector.getRecognizedBrand("www.paypal.com"),
    "paypal"
  );

  assert.equal(
    detector.getRecognizedBrand("login.safaricom.co.ke"),
    "safaricom"
  );

  assert.equal(
    detector.getRecognizedBrand("github.io"),
    "github"
  );
});

test("does not trust domains that merely contain a brand name", () => {
  assert.equal(
    detector.getRecognizedBrand("paypal.com.example.net"),
    null
  );

  assert.equal(
    detector.getRecognizedBrand("purchase.com"),
    null
  );

  assert.equal(
    detector.getRecognizedBrand("fake-paypal.example"),
    null
  );
});
