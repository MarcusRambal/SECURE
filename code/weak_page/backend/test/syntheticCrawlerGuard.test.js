import test from "node:test";
import assert from "node:assert/strict";

import { syntheticCrawlerGuard } from "../middleware/syntheticCrawlerGuard.js";

function runGuard(method, path, probeHeader) {
  const result = { status: null, body: null, continued: false };
  const req = {
    method,
    path,
    get: name => name === "x-weak-page-crawler" ? probeHeader : undefined
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
