// backend/src/controllers/admin.controller.js
import { db } from "../utils/sql.js";
import {
  isVulnerable, resolvedFlags, currentGlobalMode, normalizeVulnerabilityValue
} from "../config/securityMode.js";
import { VULNERABILITIES, VULNERABILITY_LEVELS } from "../config/vulnerabilities.js";
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
      VULNERABILITIES[k] = VULNERABILITY_LEVELS[k]
        ? (target ? VULNERABILITY_LEVELS[k].min : VULNERABILITY_LEVELS[k].secure)
        : target;
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
  const normalizedValue = normalizeVulnerabilityValue(flag, value);
  if (normalizedValue === null) {
    return res.status(400).json({ message: "Nivel inválido", flag, value });
  }
  VULNERABILITIES[flag] = normalizedValue;
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