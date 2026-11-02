import { getOrder } from "../services/orderService.js";
import { formatDate, formatPrice } from "../utils/format.js";
import { loader } from "../components/loader.js";
import { emptyState } from "../components/emptyState.js";

export async function renderOrderConfirmation(id) {
  let order;
  try { order = await getOrder(id); }
  catch (error) { return `<main class="container">${emptyState({ icon: "📦", title: "No encontramos tu pedido", message: error.message, action: '<a class="button" href="#/catalog">Volver al catálogo</a>' })}</main>`; }
  return `<main class="container"><section class="confirmation">
    <div class="confirmation-icon" aria-hidden="true">✓</div><span class="eyebrow">Pedido confirmado</span><h1>¡Gracias por tu compra!</h1>
    <p class="muted">Estamos preparando algo delicioso. Te enviaremos los detalles a ${order.customer.email}.</p>
    <div class="confirmation-summary"><div class="summary-row"><span>Número de pedido</span><strong>${order.id}</strong></div><div class="summary-row"><span>Fecha</span><span>${formatDate(order.createdAt)}</span></div>
      ${order.items.map(item => `<div class="summary-row"><span>${item.quantity} × ${item.name}</span><span>${formatPrice(item.price * item.quantity)}</span></div>`).join("")}
      <div class="summary-row"><span>Envío</span><span>${order.shipping ? formatPrice(order.shipping) : "Gratis"}</span></div><div class="summary-row summary-total"><span>Total</span><span>${formatPrice(order.total)}</span></div>
    </div><p class="muted">Método de pago: ${order.paymentMethod === "cash" ? "Efectivo al recibir" : "Tarjeta al recibir"} · Pago simulado</p>
    <a class="button" href="#/catalog">Seguir explorando</a>
  </section></main>`;
}

export function bindOrderConfirmation() {}
