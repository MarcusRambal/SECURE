import { db } from "../utils/sql.js";
import { getVulnerabilityLevel } from "../config/securityMode.js";
import { encryptCustomer, decryptCustomer } from "../utils/crypto.js";

export function createOrder({ userId, customer, items, paymentMethod }, req) {
  const subtotal = items.reduce((s, i) => s + i.price * i.quantity, 0);
  const shipping = subtotal >= 50 ? 0 : 5;
  const total = subtotal + shipping;

  const customerEncrypted = encryptCustomer(customer, req);

  const idorLevel = getVulnerabilityLevel("IDOR_ORDERS", req);
  // B1 nivel 1 conserva códigos secuenciales; los otros niveles usan códigos aleatorios.
  const code = idorLevel === 1
    ? `DN-${1000 + db.prepare("SELECT COUNT(*) AS c FROM orders").get().c}`
    : `DN-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 8)}`;

  const info = db.prepare(
    `INSERT INTO orders (code, user_id, customer_json, items_json, subtotal, shipping, total, payment_method, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmado')`
  ).run(code, userId, customerEncrypted, JSON.stringify(items), subtotal, shipping, total, paymentMethod);

  return findById(info.lastInsertRowid, req);
}

export function findById(id, req) {
  const row = db.prepare("SELECT * FROM orders WHERE id = ?").get(id);
  return row ? hydrate(row, req) : null;
}

export function findByCode(code, req) {
  const row = db.prepare("SELECT * FROM orders WHERE code = ?").get(code);
  return row ? hydrate(row, req) : null;
}

export function findByObfuscatedId(publicId, req) {
  if (!/^[A-Za-z0-9_-]+$/.test(publicId)) return null;
  const id = Buffer.from(publicId, "base64url").toString("utf8");
  if (!/^[1-9]\d*$/.test(id) || Buffer.from(id).toString("base64url") !== publicId) {
    return null;
  }
  return findById(Number(id), req);
}

export function findByUser(userId, req) {
  const rows = db.prepare("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC").all(userId);
  return rows.map((r) => hydrate(r, req));
}

export function listAll(req) {
  const rows = db.prepare("SELECT * FROM orders ORDER BY id").all();
  return rows.map((r) => hydrate(r, req));
}

function hydrate(row, req) {
  const idorLevel = getVulnerabilityLevel("IDOR_ORDERS", req);
  const publicId = idorLevel === 2
    ? Buffer.from(String(row.id)).toString("base64url")
    : row.id;
  return {
    id: publicId,
    code: idorLevel === 2 ? publicId : row.code,
    user_id: row.user_id,
    customer: decryptCustomer(row.customer_json, req),
    customer_encrypted: row.customer_json, // útil para C4 (vulnerable: base64, mitigado: aes:...)
    items: JSON.parse(row.items_json),
    subtotal: row.subtotal,
    shipping: row.shipping,
    total: row.total,
    payment_method: row.payment_method,
    status: row.status,
    created_at: row.created_at
  };
}