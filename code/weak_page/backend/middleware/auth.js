import jwt from "jsonwebtoken";
import { isVulnerable } from "../config/securityMode.js";

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

  try {
    // A1: aceptar alg:none ANTES de verificar
    if (isVulnerable("JWT_ALG_NONE", req)) {
      const decoded = jwt.decode(token, { complete: true });
      if (decoded?.header?.alg?.toLowerCase() === "none") {
        req.user = decoded.payload;
        return next();
      }
    }
    // A2: secreto débil
    const secret = isVulnerable("JWT_WEAK_SECRET", req)
      ? "secret"
      : process.env.JWT_SECRET;
    req.user = jwt.verify(token, secret);
    return next();
  } catch (err) {
    return res.status(401).json({ message: "Token inválido", detail: err.message });
  }
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