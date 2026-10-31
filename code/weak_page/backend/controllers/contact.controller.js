import * as contactService from "../services/contact.service.js";
import { isVulnerable } from "../config/securityMode.js";

/**
 * POST /api/contact
 * El mensaje se guarda en crudo. En modo vulnerable se devuelve el "echo"
 * completo, útil para que un "gracias por tu mensaje" del frontend lo
 * renderice y dispare el XSS.
 */
export function sendContact(req, res, next) {
  try {
    const { name, email, subject, message } = req.body || {};
    if (!name || !email || !message) {
      return res.status(400).json({ message: "Nombre, email y mensaje son obligatorios" });
    }
    const stored = contactService.save({ name, email, subject, message });
    const body = { ok: true, id: stored.id };
    if (isVulnerable("XSS_STORED_CONTACT", req)) {
      // ❌ devolvemos el mensaje tal cual; el frontend decide si lo inyecta
      body.echo = stored;
    }
    res.status(201).json(body);
  } catch (err) { next(err); }
}

/**
 * GET /api/contact — bandeja de entrada (reto I5 cuando el admin la vea).
 * En vulnerable: devuelve los mensajes con HTML crudo.
 */
export function listContacts(req, res) {
  res.json({ items: contactService.listAll(req) });
}