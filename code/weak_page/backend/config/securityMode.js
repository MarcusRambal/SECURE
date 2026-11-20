import { VULNERABILITIES, VULNERABILITY_LEVELS } from "./vulnerabilities.js";

const GLOBAL_MODE = process.env.SECURITY_MODE || "vulnerable"; // "vulnerable" | "secure"

/**
 * Devuelve true si la vulnerabilidad `flag` debe comportarse de forma
 * VULNERABLE para esta petición.
 *
 * Precedencia:
 *   1. Override por request (header X-Vulnerability-Override / X-Security-Mode)
 *   2. Modo global (SECURITY_MODE=secure → todo a false)
 *   3. Valor del flag en VULNERABILITIES
 *
 * @param {string} flag   Nombre del flag (p.ej. "SQLI_LOGIN")
 * @param {Request} [req] Request de Express (opcional, para overrides)
 * @returns {boolean}
 */
export function isVulnerable(flag, req) {
  const levelConfig = VULNERABILITY_LEVELS[flag];
  if (levelConfig) {
    const level = getVulnerabilityLevel(flag, req);
    return level <= levelConfig.vulnerableThrough;
  }
  if (req?.vulnerabilityOverrides?.[flag] !== undefined) {
    return req.vulnerabilityOverrides[flag] === true;
  }
  if (GLOBAL_MODE === "secure") return false;
  return VULNERABILITIES[flag] === true;
}

export function normalizeVulnerabilityValue(flag, value, secureMode = false) {
  const levelConfig = VULNERABILITY_LEVELS[flag];
  if (!levelConfig) return Boolean(value);

  if (typeof value === "boolean") {
    if (value) return levelConfig.min;
    return secureMode ? levelConfig.secure : levelConfig.legacyFalse;
  }

  const level = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (Number.isInteger(level) && level >= levelConfig.min && level <= levelConfig.max) {
    return level;
  }
  return null;
}

export function getVulnerabilityLevel(flag, req) {
  const levelConfig = VULNERABILITY_LEVELS[flag];
  if (!levelConfig) return null;

  const override = req?.vulnerabilityOverrides?.[flag];
  if (override !== undefined) {
    return normalizeVulnerabilityValue(flag, override) ?? levelConfig.secure;
  }
  if (GLOBAL_MODE === "secure") return levelConfig.secure;
  return normalizeVulnerabilityValue(flag, VULNERABILITIES[flag]) ?? levelConfig.secure;
}

/**
 * Devuelve una copia del mapa de flags ya resuelta para esta request.
 * Útil para el endpoint de estado / scoreboard.
 */
export function resolvedFlags(req) {
  const out = {};
  for (const flag of Object.keys(VULNERABILITIES)) {
    out[flag] = VULNERABILITY_LEVELS[flag]
      ? getVulnerabilityLevel(flag, req)
      : isVulnerable(flag, req);
  }
  return out;
}

export const currentGlobalMode = () => GLOBAL_MODE;