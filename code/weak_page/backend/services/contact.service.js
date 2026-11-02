import { db } from "../utils/sql.js";
import { isVulnerable } from "../config/securityMode.js";
import { escapeHtml } from "../utils/html.js";

/**
 * Guarda el mensaje SIEMPRE en crudo (la BD es canónica).
 * La decisión de escapar o no se toma al servir (listAll).
 */
export function save({ name, email, subject = "", message }) {
  const info = db.prepare(
    "INSERT INTO contact_messages (name, email, subject, message) VALUES (?, ?, ?, ?)"
  ).run(name, email, subject, message);
  return db.prepare("SELECT * FROM contact_messages WHERE id = ?").get(info.lastInsertRowid);
}

export function deleteValidationProbe(id, marker) {
  return db.prepare(
    "DELETE FROM contact_messages WHERE id = ? AND instr(message, ?) > 0"
  ).run(id, marker).changes;
}

export function getValidationProbe(id, marker, req) {
  const row = db.prepare(
    "SELECT * FROM contact_messages WHERE id = ? AND instr(message, ?) > 0"
  ).get(id, marker);
  if (!row || isVulnerable("XSS_STORED_CONTACT", req)) return row;
  return {
    ...row,
    name: escapeHtml(row.name || ""),
    email: escapeHtml(row.email || ""),
    subject: escapeHtml(row.subject || ""),
    message: escapeHtml(row.message || "")
  };
}

/**
 * Reto I5 — XSS almacenado.
 *   vulnerable: devuelve el mensaje tal cual (el frontend lo inyectará con innerHTML)
 *   seguro:     escapa campos HTML antes de devolver
 */
export function listAll(req) {
  const rows = db.prepare(
    "SELECT * FROM contact_messages ORDER BY created_at DESC"
  ).all();

  if (isVulnerable("XSS_STORED_CONTACT", req)) return rows;

  return rows.map((r) => ({
    ...r,
    name: escapeHtml(r.name || ""),
    email: escapeHtml(r.email || ""),
    subject: escapeHtml(r.subject || ""),
    message: escapeHtml(r.message || "")
  }));
}