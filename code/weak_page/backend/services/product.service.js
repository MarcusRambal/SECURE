import { db } from "../utils/sql.js";
import { isVulnerable } from "../config/securityMode.js";

const PRODUCT_COLS =
  "id, name, category, price, description, image, stock, featured, ingredients, allergens";

/**
 * Construye la SQL de listado respetando I2 (SQLi en q) e I3 (UNION en category).
 * Devuelve { sql, params } sin ejecutar. El controller captura errores.
 */
export function buildListQuery(req, { q, category, featured }) {
  const params = [];
  let sql = `SELECT ${PRODUCT_COLS} FROM products WHERE 1=1`;

  if (featured) {
    sql += " AND featured = 1";
  }

  if (category && category !== "all") {
    if (isVulnerable("UNION_SQLI_DUMP", req)) {
      sql += ` AND category = '${category}'`;  // ❌ concatenación directa
    } else {
      sql += " AND category = ?";
      params.push(category);
    }
  }

  if (q) {
    if (isVulnerable("SQLI_SEARCH", req)) {
      sql += ` AND name LIKE '%${q}%'`;        // ❌ concatenación directa
    } else {
      sql += " AND name LIKE ?";
      params.push(`%${q}%`);
    }
  }

  return { sql, params };
}

export function findById(id) {
  return db.prepare(`SELECT ${PRODUCT_COLS} FROM products WHERE id = ?`).get(id);
}

export function findRelated(productId, limit = 4) {
  const current = findById(productId);
  if (!current) return [];
  return db.prepare(
    `SELECT ${PRODUCT_COLS} FROM products WHERE id != ? AND category = ? LIMIT ?`
  ).all(productId, current.category, limit);
}

export function listCategories() {
  return db.prepare("SELECT DISTINCT category FROM products ORDER BY category")
    .all()
    .map((r) => r.category);
}