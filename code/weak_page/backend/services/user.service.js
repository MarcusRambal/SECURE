import bcrypt from "bcrypt";
import crypto from "node:crypto";
import { db } from "../utils/sql.js";
import { isVulnerable } from "../config/securityMode.js";

const md5 = (s) => crypto.createHash("md5").update(s).digest("hex");

/**
 * Detecta el formato de una contraseña almacenada:
 *   - bcrypt: "$2a$..." / "$2b$..." / "$2y$..."
 *   - md5:    32 caracteres hexadecimales
 *   - plain:  cualquier otro texto
 */
export function detectFormat(stored) {
  if (!stored) return "unknown";
  if (/^\$2[aby]\$\d{2}\$/.test(stored)) return "bcrypt";
  if (/^[a-f0-9]{32}$/i.test(stored)) return "md5";
  return "plain";
}

/**
 * Verifica una contraseña respetando C1 (plaintext) y C2 (MD5 legacy).
 */
export async function verifyPassword(plain, stored, req) {
  const format = detectFormat(stored);

  if (format === "bcrypt") {
    return bcrypt.compare(plain, stored);
  }
  if (format === "md5") {
    // C2 desactivado → rechaza MD5 (el usuario debe resetear contraseña)
    if (!isVulnerable("WEAK_MD5_LEGACY", req)) return false;
    return md5(plain) === stored;
  }
  // plain
  if (!isVulnerable("PLAINTEXT_PASSWORDS", req)) return false;
  return plain === stored;
}

/**
 * Prepara una contraseña para almacenar respetando C1.
 */
export async function preparePassword(plain, req) {
  if (isVulnerable("PLAINTEXT_PASSWORDS", req)) return plain;
  return bcrypt.hash(plain, 12);
}

/**
 * Elimina campos sensibles antes de devolver el usuario al cliente.
 */
export function safeUser(user) {
  if (!user) return null;
  const { password, reset_token, reset_expires, ...rest } = user;
  return rest;
}

export function findUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(email);
}

export function findUserById(id) {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}