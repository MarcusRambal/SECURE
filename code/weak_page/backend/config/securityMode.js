import { VULNERABILITIES } from "./vulnerabilities.js";

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
  if (req?.vulnerabilityOverrides?.[flag] !== undefined) {
    return req.vulnerabilityOverrides[flag];
  }
  if (GLOBAL_MODE === "secure") return false;
  return VULNERABILITIES[flag] === true;
}

/**
 * Devuelve una copia del mapa de flags ya resuelta para esta request.
 * Útil para el endpoint de estado / scoreboard.
 */
export function resolvedFlags(req) {
  const out = {};
  for (const flag of Object.keys(VULNERABILITIES)) {
    out[flag] = isVulnerable(flag, req);
  }
  return out;
}

export const currentGlobalMode = () => GLOBAL_MODE;