import { db } from "../utils/sql.js";
import { isVulnerable } from "../config/securityMode.js";
import { escapeHtml } from "../utils/html.js";
import * as productService from "../services/product.service.js";

/**
 * GET /api/products
 * Retos: I2 (SQLi q), I3 (UNION category), I4 (XSS reflejado en searchInfo.rendered)
 */
export function listProducts(req, res, next) {
  const q = typeof req.query.q === "string" ? req.query.q : "";
  const category = typeof req.query.category === "string" ? req.query.category : "all";
  const featured = req.query.featured === "true";

  // I4 — XSS reflejado: el frontend inyectará searchInfo.rendered con innerHTML
  let searchInfo = null;
  if (q) {
    if (isVulnerable("XSS_REFLECTED_SEARCH", req)) {
      // ❌ sin escapar → si el frontend usa innerHTML, XSS
      searchInfo = { raw: q, rendered: `<b>Resultados para:</b> ${q}` };
    } else {
      // ✅ escapado en el backend
      searchInfo = { raw: q, rendered: `<b>Resultados para:</b> ${escapeHtml(q)}` };
    }
  }

  let attemptedSql = null;
  try {
    const built = productService.buildListQuery(req, { q, category, featured });
    attemptedSql = built.sql;
    const rows = db.prepare(built.sql).all(...built.params);
    return res.json({ items: rows, searchInfo });
  } catch (err) {
    // ❌ modo vulnerable: exponemos la SQL que falló (parte del reto I3)
    err.sql = attemptedSql;
    return next(err);
  }
}

export function getProduct(req, res) {
  const product = productService.findById(req.params.id);
  if (!product) return res.status(404).json({ message: "Producto no encontrado" });
  res.json(product);
}

export function getRelatedProducts(req, res) {
  res.json(productService.findRelated(req.params.id));
}

export function listCategories(_req, res) {
  res.json(productService.listCategories());
}