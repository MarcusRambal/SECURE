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

export function getValidationProbe(req, res) {
  if (
    process.env.NODE_ENV === "production" ||
    req.get("x-weak-page-xss-validation") !== "stored-contact"
  ) {
    return res.status(404).json({ message: "Recurso no encontrado" });
  }
  const id = Number(req.params.id);
  const marker = req.query.marker;
  if (
    !Number.isSafeInteger(id) ||
    id < 1 ||
    typeof marker !== "string" ||
    !/^weakpage-xss-probe-[a-f0-9]{12}$/.test(marker)
  ) {
    return res.status(400).json({ message: "Identificador de prueba inválido" });
  }
  const item = contactService.getValidationProbe(id, marker, req);
  if (!item) return res.status(404).json({ message: "Registro de prueba no encontrado" });
  res.json({ item });
}

export function deleteValidationProbe(req, res) {
  if (
    process.env.NODE_ENV === "production" ||
    req.get("x-weak-page-xss-validation") !== "stored-contact"
  ) {
    return res.status(404).json({ message: "Recurso no encontrado" });
  }
  const id = Number(req.params.id);
  const marker = req.body?.marker;
  if (
    !Number.isSafeInteger(id) ||
    id < 1 ||
    typeof marker !== "string" ||
    !/^weakpage-xss-probe-[a-f0-9]{12}$/.test(marker)
  ) {
    return res.status(400).json({ message: "Identificador de prueba inválido" });
  }
  if (!contactService.deleteValidationProbe(id, marker)) {
    return res.status(404).json({ message: "Registro de prueba no encontrado" });
  }
  res.status(204).end();
}