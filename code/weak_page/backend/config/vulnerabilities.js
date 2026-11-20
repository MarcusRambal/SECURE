// ============================================================
// MAPA DE VULNERABILIDADES — 20 retos, 4 categorías × 5
// ============================================================
// Cada flag corresponde a un reto independiente.
//   true  → comportamiento VULNERABLE
//   false → comportamiento SEGURO (mitigado)
//
// Override por request (útil en Postman/Burp para pruebas A/B):
//   Header: X-Vulnerability-Override: SQLI_LOGIN=false,IDOR_ORDERS=true
// Override global (todos seguros):
//   Header: X-Security-Mode: secure
//   O bien: SECURITY_MODE=secure en .env
// ============================================================
export const VULNERABILITY_LEVELS = {
  IDOR_ORDERS: { min: 1, max: 3, secure: 3, legacyFalse: 3, vulnerableThrough: 2 },
  JWT_NO_EXPIRY: { min: 1, max: 4, secure: 4, legacyFalse: 3, vulnerableThrough: 2 }
};

export const VULNERABILITIES = {
  // ────────────────────────────────────────────────────────────
  // 💉 INJECTION (5)
  // ────────────────────────────────────────────────────────────
  SQLI_LOGIN:               true, // I1 — bypass de login con SQLi
  SQLI_SEARCH:              true, // I2 — SQLi en búsqueda de productos
  UNION_SQLI_DUMP:          true, // I3 — UNION en ?category= para dumpear tablas
  XSS_REFLECTED_SEARCH:     true, // I4 — XSS reflejado en ?q=
  XSS_STORED_CONTACT:       true, // I5 — XSS almacenado en contacto

  // ────────────────────────────────────────────────────────────
  // 🔐 CRYPTOGRAPHIC FAILURES (5)
  // ────────────────────────────────────────────────────────────
  PLAINTEXT_PASSWORDS:      true, // C1 — registros nuevos en texto plano
  WEAK_MD5_LEGACY:          true, // C2 — usuarios seed con MD5 (crackeables)
  PREDICTABLE_RESET_TOKEN:  true, // C3 — token de reset = md5(email)
  BASE64_FAKE_ENCRYPTION:   true, // C4 — PII "cifrada" en base64
  HARDCODED_CRYPTO_SECRET:  true, // C5 — clave en el código fuente

  // ────────────────────────────────────────────────────────────
  // 🚪 BROKEN ACCESS CONTROL (5)
  // ────────────────────────────────────────────────────────────
  IDOR_ORDERS:              1,    // B1 — 1 secuencial, 2 ofuscado, 3 valida dueño
  MISSING_AUTH_ME:          true, // B2 — /me y /orders aceptan sin token
  EXPOSED_SENSITIVE_FILES:  true, // B3 — .env, backup.sql, logs servidos
  MISSING_ROLE_CHECK_ADMIN: true, // B4 — /admin/* accesible por cualquier user
  MASS_ASSIGNMENT_REGISTER: true, // B5 — registro acepta role:"admin"

  // ────────────────────────────────────────────────────────────
  // 🔑 AUTHENTICATION FAILURES (5)
  // ────────────────────────────────────────────────────────────
  JWT_ALG_NONE:             true, // A1 — acepta tokens sin firma
  JWT_WEAK_SECRET:          true, // A2 — firma con "secret"
  JWT_NO_EXPIRY:            1,    // A3 — niveles de emisión y validación de expiración
  USER_ENUMERATION:         true, // A4 — login revela si el email existe
  WEAK_PASSWORD_NO_RATELIMIT:true// A5 — sin política ni rate limit
};