import test from "node:test";
import assert from "node:assert/strict";

import { syntheticCrawlerGuard } from "../middleware/syntheticCrawlerGuard.js";

function runGuard(method, path, probeHeader, validationHeader, body = {}, query = {}) {
  const result = { status: null, body: null, continued: false };
  const req = {
    method,
    path,
    body,
    query,
    get: name => {
      if (name === "x-weak-page-crawler") return probeHeader;
      if (name === "x-weak-page-xss-validation") return validationHeader;
      return undefined;
    }
  };
  const res = {
    status(code) {
      result.status = code;
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    }
  };
  syntheticCrawlerGuard(req, res, () => {
    result.continued = true;
  });
  return result;
}

test("rejects synthetic write probes before the application handler", () => {
  const result = runGuard("POST", "/contact", "synthetic-probe");

  assert.equal(result.status, 422);
  assert.equal(result.continued, false);
  assert.equal(
    result.body.message,
    "Synthetic weakPageCrawler write probe rejected."
  );
});

test("lets the synthetic invalid login reach authentication validation", () => {
  const result = runGuard("POST", "/auth/login", "synthetic-probe");

  assert.equal(result.status, null);
  assert.equal(result.continued, true);
});

test("does not change writes without the crawler marker", () => {
  const result = runGuard("POST", "/contact", undefined);

  assert.equal(result.status, null);
  assert.equal(result.continued, true);
});

test("allows only a tagged weak_page contact XSS probe outside production", () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  const result = runGuard(
    "POST",
    "/contact",
    undefined,
    "stored-contact",
    { message: "weakpage-xss-probe-a1b2c3d4e5f6<img src=x>" }
  );
  if (previous === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previous;

  assert.equal(result.status, null);
  assert.equal(result.continued, true);
});

test("allows only a marked single-contact read for the stored-XSS proof", () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  const result = runGuard(
    "GET",
    "/contact/xss-inbox/42",
    undefined,
    "stored-contact",
    {},
    { marker: "weakpage-xss-probe-a1b2c3d4e5f6" }
  );
  const invalid = runGuard(
    "GET",
    "/contact",
    undefined,
    "stored-contact",
    {},
    { marker: "weakpage-xss-probe-a1b2c3d4e5f6" }
  );
  if (previous === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previous;

  assert.equal(result.status, null);
  assert.equal(result.continued, true);
  assert.equal(invalid.status, 422);
  assert.equal(invalid.continued, false);
});

test("rejects unmarked or malformed XSS validation writes", () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  const invalid = runGuard(
    "POST",
    "/contact",
    undefined,
    "stored-contact",
    { message: "<img src=x>" }
  );
  const otherRoute = runGuard(
    "POST",
    "/orders",
    undefined,
    "stored-contact",
    { message: "weakpage-xss-probe-a1b2c3d4e5f6<img>" }
  );
  if (previous === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previous;

  assert.equal(invalid.status, 422);
  assert.equal(otherRoute.status, 422);
});

test("rejects XSS validation writes in production", () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  const result = runGuard(
    "POST",
    "/contact",
    undefined,
    "stored-contact",
    { message: "weakpage-xss-probe-a1b2c3d4e5f6<img>" }
  );
  if (previous === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = previous;

  assert.equal(result.status, 422);
  assert.equal(result.continued, false);
});
