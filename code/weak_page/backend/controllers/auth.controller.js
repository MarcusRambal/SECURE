import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { db } from "../utils/sql.js";
import { isVulnerable } from "../config/securityMode.js";
import {
  verifyPassword, preparePassword, safeUser,
  findUserByEmail, findUserById
} from "../services/user.service.js";

const md5 = (s) => crypto.createHash("md5").update(s).digest("hex");

/**
 * Emite un JWT respetando A2 (secreto débil) y A3 (sin expiración).
 * El algoritmo HS256 se declara explícitamente para que `jwt.verify` con
 * `algorithms: ["HS256"]` en el middleware no dependa de defaults.
 */
function issueToken(user, req) {
  const secret = isVulnerable("JWT_WEAK_SECRET", req)
    ? "secret"
    : process.env.JWT_SECRET;
  const options = {
    algorithm: "HS256",
    ...(isVulnerable("JWT_NO_EXPIRY", req) ? {} : { expiresIn: "1h" }),
  };
  return jwt.sign({ id: user.id, role: user.role }, secret, options);
}

// ─────────────────────────────────────────────────────────────
// POST /api/auth/login
// Retos: I1, A4, A5 (rate limit se aplica en la ruta)
// ─────────────────────────────────────────────────────────────
export async function login(req, res, next) {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "Email y contraseña obligatorios" });
    }

    let user;

    // I1: SQL Injection directa
    if (isVulnerable("SQLI_LOGIN", req)) {
      // ❌ Concatenación directa
      const passwordHash = md5(String(password));
      const sql = `SELECT * FROM users WHERE email = '${email}' AND (password = '${password}' OR password = '${passwordHash}')`;
      try {
        user = db.prepare(sql).get();
      } catch (err) {
        err.sql = sql;
        return next(err); // errorHandler devuelve stack + SQL en modo vulnerable
      }
    } else {
      // ✅ Login seguro
      user = findUserByEmail(email);
      if (user) {
        const ok = await verifyPassword(password, user.password, req);
        if (!ok) user = null;
      }
    }

    // A4: enumeración de usuarios (independiente de SQLI_LOGIN)
    if (!user) {
      if (isVulnerable("USER_ENUMERATION", req)) {
        const exists = findUserByEmail(email);
        return res.status(401).json({
          message: exists ? "Contraseña incorrecta" : "Usuario no existe"
        });
      }
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    const token = issueToken(user, req);
    return res.json({ user: safeUser(user), token });
  } catch (err) { next(err); }
}

// ─────────────────────────────────────────────────────────────
// POST /api/auth/register
// Retos: B5, C1, A5
// ─────────────────────────────────────────────────────────────
export async function register(req, res, next) {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Faltan campos obligatorios" });
    }

    // A5: política débil (solo aplica si el flag está OFF)
    if (!isVulnerable("WEAK_PASSWORD_NO_RATELIMIT", req)) {
      if (password.length < 8) {
        return res.status(400).json({ message: "Mínimo 8 caracteres" });
      }
      if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
        return res.status(400).json({ message: "Debe contener mayúscula y número" });
      }
    }

    // B5: mass assignment — acepta role:"admin" en el body
    let role = "customer";
    if (isVulnerable("MASS_ASSIGNMENT_REGISTER", req) && req.body.role) {
      role = req.body.role;
    }

    if (findUserByEmail(email)) {
      return res.status(409).json({ message: "Ese email ya está registrado" });
    }

    // C1: contraseña plana vs bcrypt
    const storedPassword = await preparePassword(password, req);

    const info = db.prepare(
      "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run(name, email, storedPassword, role);

    const user = findUserById(info.lastInsertRowid);
    const token = issueToken(user, req);
    return res.status(201).json({ user: safeUser(user), token });
  } catch (err) { next(err); }
}

// ─────────────────────────────────────────────────────────────
// GET /api/me
// Retos: B2 (auth ausente)
// ─────────────────────────────────────────────────────────────
export async function me(req, res, next) {
  try {
    if (!req.user) {
      if (isVulnerable("MISSING_AUTH_ME", req)) {
        // ❌ Sin token → devolvemos el primer admin (reto B2)
        const fallback = db.prepare("SELECT * FROM users WHERE role = 'admin' LIMIT 1").get();
        return res.json({ user: safeUser(fallback), _vulnerable: "MISSING_AUTH_ME" });
      }
      return res.status(401).json({ message: "No autenticado" });
    }
    const user = findUserById(req.user.id);
    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });
    return res.json({ user: safeUser(user) });
  } catch (err) { next(err); }
}

// ─────────────────────────────────────────────────────────────
// GET /api/auth/whoami
// Endpoint estable para pruebas JWT (jwt_tool / SECURE).
// - Siempre exige token (requireStrictAuth NO cae al bypass de MISSING_AUTH_ME).
// - Devuelve 401 sin token, 200 con token válido o forjado (según flags).
// - No depende de ningún flag de BAC ni de Categorías de otro grupo.
// ─────────────────────────────────────────────────────────────
export async function whoami(req, res, next) {
  try {
    const user = findUserById(req.user?.id);
    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });
    return res.json({ user: safeUser(user) });
  } catch (err) { next(err); }
}

// ─────────────────────────────────────────────────────────────
// POST /api/auth/logout
// JWT stateless: no hay nada que invalidar server-side
// ─────────────────────────────────────────────────────────────
export async function logout(_req, res) {
  return res.json({ ok: true });
}

// ─────────────────────────────────────────────────────────────
// POST /api/auth/forgot
// Reto: C3 (token predecible)
// ─────────────────────────────────────────────────────────────
export async function forgotPassword(req, res, next) {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: "Email obligatorio" });

    const user = findUserByEmail(email);

    if (isVulnerable("PREDICTABLE_RESET_TOKEN", req)) {
      // ❌ token = md5(email), sin TTL
      const token = md5(email);
      if (user) {
        db.prepare("UPDATE users SET reset_token = ?, reset_expires = NULL WHERE id = ?")
          .run(token, user.id);
      }
      console.log(`[RESET] token para ${email}: ${token}`);
      // Exponemos el token en la respuesta: parte del laboratorio (info leak)
      return res.json({
        message: "Si el correo existe, enviamos un enlace",
        _debug_token: token
      });
    }

    // ✅ Token aleatorio + TTL 15 min
    if (!user) return res.json({ message: "Si el correo existe, enviamos un enlace" });
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    db.prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?")
      .run(token, expires, user.id);
    console.log(`[RESET] token para ${email}: ${token}`);
    return res.json({ message: "Si el correo existe, enviamos un enlace" });
  } catch (err) { next(err); }
}

// ─────────────────────────────────────────────────────────────
// POST /api/auth/reset-password
// Reto: C3 (acepta token predecible)
// ─────────────────────────────────────────────────────────────
export async function resetPassword(req, res, next) {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) {
      return res.status(400).json({ message: "Token y contraseña obligatorios" });
    }

    let user;
    if (isVulnerable("PREDICTABLE_RESET_TOKEN", req)) {
      // ❌ Acepta cualquier token == reset_token (que es md5(email))
      user = db.prepare("SELECT * FROM users WHERE reset_token = ?").get(token);
    } else {
      // ✅ Verifica TTL
      user = db.prepare(
        "SELECT * FROM users WHERE reset_token = ? AND reset_expires > datetime('now')"
      ).get(token);
    }

    if (!user) return res.status(400).json({ message: "Token inválido o expirado" });

    const stored = await preparePassword(newPassword, req);
    db.prepare(
      "UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?"
    ).run(stored, user.id);

    return res.json({ ok: true, message: "Contraseña actualizada" });
  } catch (err) { next(err); }
}