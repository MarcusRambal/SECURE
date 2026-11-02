// backend/src/controllers/admin.controller.js
import { db } from "../utils/sql.js";
import { isVulnerable, resolvedFlags, currentGlobalMode } from "../config/securityMode.js";
import { VULNERABILITIES } from "../config/vulnerabilities.js";
import { getCryptoDebugInfo } from "../utils/crypto.js";

export function listAllUsers(req, res) {
  const users = db.prepare(
    "SELECT id, name, email, password, role, created_at FROM users"
  ).all();
  res.json({
    items: users,
    _warning: isVulnerable("MISSING_ROLE_CHECK_ADMIN", req)
      ? "MISSING_ROLE_CHECK_ADMIN activo: exponiendo contraseñas a cualquier usuario"
      : undefined
  });
}

export function getVulnerabilities(req, res) {
  res.json({
    flags: resolvedFlags(req),
    securityMode: currentGlobalMode()
  });
}

export function toggleVulnerabilities(req, res) {
  const { flag, value, all } = req.body || {};

  // ▼ Botón maestro: { all: true, value: false } → todas mitigadas
  if (all === true) {
    const target = Boolean(value);
    for (const k of Object.keys(VULNERABILITIES)) {
      VULNERABILITIES[k] = target;
    }
    return res.json({
      ok: true,
      all: true,
      value: target,
      flags: resolvedFlags(req)
    });
  }

  // ▼ Toggle individual: { flag: "SQLI_LOGIN", value: false }
  if (!Object.prototype.hasOwnProperty.call(VULNERABILITIES, flag)) {
    return res.status(400).json({ message: "Flag desconocido", flag });
  }
  VULNERABILITIES[flag] = Boolean(value);
  return res.json({
    ok: true,
    flag,
    value: VULNERABILITIES[flag],
    flags: resolvedFlags(req)
  });
}

export function cryptoDebug(req, res) {
  const info = getCryptoDebugInfo(req);
  if (!info) return res.status(404).json({ message: "No encontrado" });
  res.json(info);
}