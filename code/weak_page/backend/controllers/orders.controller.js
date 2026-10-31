import { isVulnerable } from "../config/securityMode.js";
import * as orderService from "../services/order.service.js";
import { findById as findProductById } from "../services/product.service.js";

export function createOrder(req, res, next) {
  try {
    const { customer, items, paymentMethod } = req.body || {};
    if (!customer || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: "Faltan customer o items" });
    }

    // Los precios SIEMPRE se recalculan desde la BD (no es un reto del lab)
    const processedItems = items.map((i) => {
      const product = findProductById(i.productId);
      if (!product) throw new Error(`Producto ${i.productId} no existe`);
      return {
        productId: product.id,
        name: product.name,
        price: product.price,
        quantity: Number(i.quantity) || 1
      };
    });

    const userId = req.user?.id || null;
    const order = orderService.createOrder({ userId, customer, items: processedItems, paymentMethod }, req);
    return res.status(201).json(order);
  } catch (err) { next(err); }
}

/**
 * GET /api/orders/:id
 * Acepta id numérico o code (DN-XXXX) para facilitar el frontend.
 * B1 IDOR: no comprueba dueño.
 */
export function getOrder(req, res, next) {
  try {
    const param = req.params.id;
    const lookup = Number.isNaN(Number(param))
      ? (r) => orderService.findByCode(r, req)
      : (r) => orderService.findById(Number(r), req);

    const order = lookup(param);
    if (!order) return res.status(404).json({ message: "Pedido no encontrado" });

    // B1: sin comprobación de dueño
    if (isVulnerable("IDOR_ORDERS", req)) return res.json(order);

    // ✅ Seguro: comprobar dueño o admin
    if (!req.user) return res.status(401).json({ message: "No autenticado" });
    if (order.user_id !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ message: "No autorizado" });
    }
    return res.json(order);
  } catch (err) { next(err); }
}

/**
 * GET /api/orders
 * B2 MISSING_AUTH_ME: sin token devuelve TODOS los pedidos.
 */
export function listOrders(req, res, next) {
  try {
    if (!req.user) {
      if (isVulnerable("MISSING_AUTH_ME", req)) {
        return res.json({ items: orderService.listAll(req) });
      }
      return res.status(401).json({ message: "No autenticado" });
    }
    return res.json({ items: orderService.findByUser(req.user.id, req) });
  } catch (err) { next(err); }
}