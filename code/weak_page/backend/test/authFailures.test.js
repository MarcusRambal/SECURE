// code/weak_page/backend/test/authFailures.test.js
import test from "node:test";
import assert from "node:assert/strict";

import { login } from "../controllers/auth.controller.js";

const KNOWN_EMAIL = "admin@dulcenube.com";
const UNKNOWN_EMAIL = "auth-failures-missing@example.invalid";
const INVALID_PASSWORD = "__auth_failures_test_invalid_password__";

async function loginMessage(email, vulnerabilityOverrides, password = INVALID_PASSWORD) {
  const result = { status: null, body: null, error: null };
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

  await login(
    { body: { email, password }, vulnerabilityOverrides },
    res,
    error => {
      result.error = error;
    }
  );

  assert.equal(result.error, null);
  assert.equal(result.status, 401);
  return result.body.message;
}

async function messagesFor(vulnerabilityOverrides, password) {
  return {
    known: await loginMessage(KNOWN_EMAIL, vulnerabilityOverrides, password),
    unknown: await loginMessage(UNKNOWN_EMAIL, vulnerabilityOverrides, password)
  };
}

test("A4 ON distinguishes known and unknown users with SQLI_LOGIN ON", async () => {
  const messages = await messagesFor({
    USER_ENUMERATION: true,
    SQLI_LOGIN: true
  });

  assert.notEqual(messages.known, messages.unknown);
});

test("A4 OFF gives the same message with SQLI_LOGIN ON", async () => {
  const messages = await messagesFor({
    USER_ENUMERATION: false,
    SQLI_LOGIN: true
  });

  assert.equal(messages.known, messages.unknown);
});

test("A4 ON distinguishes known and unknown users with SQLI_LOGIN OFF", async () => {
  const messages = await messagesFor({
    USER_ENUMERATION: true,
    SQLI_LOGIN: false
  });

  assert.notEqual(messages.known, messages.unknown);
});

test("A4 OFF stays generic with SQLI_LOGIN ON for another invalid password", async () => {
  const messages = await messagesFor(
    { USER_ENUMERATION: false, SQLI_LOGIN: true },
    "__another_auth_failures_test_password__"
  );

  assert.equal(messages.known, messages.unknown);
});