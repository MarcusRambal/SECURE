import jwt from "jsonwebtoken";
import { isVulnerable } from "../config/securityMode.js";

/**
 * Verificación compartida por requireAuth y requireStrictAuth.
 * - A1 JWT_ALG_NONE:    acepta tokens sin firma (alg:none).
 * - A2 JWT_WEAK_SECRET: verifica con "secret" en vez de process.env.JWT_SECRET.
 * - HS256 se declara explícitamente en `verify` para no depender de defaults.
 */
function _verifyToken(req, token) {
  if (isVulnerable("JWT_ALG_NONE", req)) {
    const decoded = jwt.decode(token, { complete: true });
    if (decoded?.header?.alg?.toLowerCase() === "none") {
      return { ok: true, user: decoded.payload };
    }
  }
  try {
    const secret = isVulnerable("JWT_WEAK_SECRET", req)
      ? "secret"
      : process.env.JWT_SECRET;
    const user = jwt.verify(token, secret, { algorithms: ["HS256"] });
    return { ok: true, user };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Middleware de autenticación con comportamiento dependiente de flags.
 *
 *   - B2 MISSING_AUTH_ME: si no hay token, deja pasar con req.user = null
 *   - A1 JWT_ALG_NONE:    acepta tokens sin firma (alg:none)
 *   - A2 JWT_WEAK_SECRET: verifica con "secret" en vez de process.env.JWT_SECRET
 */
export function requireAuth(req, res, next) {
  // B2: en modo vulnerable, no exigir token
  if (isVulnerable("MISSING_AUTH_ME", req) && !req.headers.authorization) {
    req.user = null;
    return next();
  }

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Token requerido" });

  const result = _verifyToken(req, token);
  if (!result.ok) {
    return res.status(401).json({ message: "Token inválido", detail: result.error });
  }
  req.user = result.user;
  return next();
}

/**
 * Auth estricta para endpoints que NUNCA deben caer al bypass de
 * MISSING_AUTH_ME (BAC). Es la variante que usa /api/auth/whoami para
 * pruebas JWT de SECURE / jwt_tool.
 */
export function requireStrictAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Token requerido" });

  const result = _verifyToken(req, token);
  if (!result.ok) {
    return res.status(401).json({ message: "Token inválido", detail: result.error });
  }
  req.user = result.user;
  return next();
}

/**
 * requireRole: no lleva flag propio — su ausencia se controla con
 * MISSING_ROLE_CHECK_ADMIN en cada ruta de admin (Parte 4).
 */
export function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: "No autenticado" });
    if (req.user.role !== role) return res.status(403).json({ message: "Acceso denegado" });
    next();
  };
}