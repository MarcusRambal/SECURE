import { getState, toggleCart, updateItemQuantity, removeItem } from "../state/store.js";
import { formatPrice } from "../utils/format.js";
import { emptyState } from "./emptyState.js";

export function renderCartDrawer() {
  const { cart, cartOpen } = getState();
  if (!cartOpen) return "";
  const subtotal = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
  return `<div class="cart-backdrop" data-close-cart></div><aside class="cart-drawer" role="dialog" aria-modal="true" aria-labelledby="cart-title">
    <div class="drawer-head"><h2 id="cart-title">Tu carrito</h2><button class="icon-button" type="button" data-close-cart aria-label="Cerrar carrito">×</button></div>
    <div class="drawer-items">${cart.length ? cart.map(item => `<div class="cart-line">
      <img src="${item.image}" alt="" /><div><h3>${item.name}</h3><span class="muted">${formatPrice(item.price)}</span></div>
      <div class="quantity-control"><button type="button" data-cart-quantity="${item.productId}" data-delta="-1" aria-label="Restar uno">−</button><span>${item.quantity}</span><button type="button" data-cart-quantity="${item.productId}" data-delta="1" aria-label="Sumar uno">+</button></div>
      <button class="remove-button" type="button" data-remove-item="${item.productId}" aria-label="Quitar ${item.name}">×</button>
    </div>`).join("") : emptyState({ icon: "🧁", title: "Aún está vacío", message: "Descubre algo rico para compartir." })}</div>
    ${cart.length ? `<div class="drawer-footer"><div class="summary-row"><span>Subtotal</span><strong>${formatPrice(subtotal)}</strong></div><a class="button" href="#/checkout" id="checkout-link">Continuar al pedido</a></div>` : ""}
  </aside>`;
}

export function bindCartDrawer() {
  document.querySelectorAll("[data-close-cart]").forEach(node => node.addEventListener("click", () => toggleCart(false)));
  document.querySelectorAll("[data-cart-quantity]").forEach(button => button.addEventListener("click", async () => {
    const item = getState().cart.find(entry => String(entry.productId) === button.dataset.cartQuantity);
    if (item) await updateItemQuantity(item.productId, item.quantity + Number(button.dataset.delta));
  }));
  document.querySelectorAll("[data-remove-item]").forEach(button => button.addEventListener("click", () => removeItem(button.dataset.removeItem)));
  document.querySelector("#checkout-link")?.addEventListener("click", () => toggleCart(false));
}
