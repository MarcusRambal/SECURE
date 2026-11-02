import { getState, updateItemQuantity, removeItem, clearCart } from "../state/store.js";
import { createOrder } from "../services/orderService.js";
import { formatPrice } from "../utils/format.js";
import { emptyState } from "../components/emptyState.js";
import { showToast } from "../components/toast.js";
import { validateForm, showFieldErrors } from "../utils/validators.js";

export function renderCheckout() {
  const { cart, user } = getState();
  if (!cart.length) return `<main class="container"><header class="page-intro"><span class="eyebrow">Casi casi</span><h1>Tu pedido</h1></header>${emptyState({ icon: "🧁", title: "Tu carrito está vacío", message: "Elige algo delicioso para continuar.", action: '<a class="button" href="#/catalog">Ir al catálogo</a>' })}</main>`;
  const subtotal = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
  const shipping = subtotal >= 50 ? 0 : 5;
  return `<main class="container"><header class="page-intro"><span class="eyebrow">Un último paso</span><h1>Tu pedido</h1><p class="muted">Revisa tus delicias y dinos dónde las llevamos.</p></header>
    <div class="checkout-layout">
      <section class="checkout-main"><h2>Tu selección</h2><div id="checkout-items">${cart.map(item => `<div class="cart-line">
        <img src="${item.image}" alt="" /><div><h3>${item.name}</h3><span class="muted">${formatPrice(item.price)} c/u</span></div>
        <div class="quantity-control"><button type="button" data-checkout-quantity="${item.productId}" data-delta="-1" aria-label="Restar uno">−</button><span>${item.quantity}</span><button type="button" data-checkout-quantity="${item.productId}" data-delta="1" aria-label="Sumar uno">+</button></div>
        <button class="remove-button" type="button" data-remove-item="${item.productId}" aria-label="Quitar ${item.name}">×</button>
      </div>`).join("")}</div>
      <h2 style="margin-top:30px">Datos de entrega</h2><div id="checkout-status" aria-live="polite"></div>
      <form class="checkout-form" id="checkout-form" novalidate>
        <div class="field"><label for="customer-name">Nombre completo</label><input id="customer-name" name="name" autocomplete="name" value="${user?.name || ""}" required /><small class="field-error" data-error-for="name"></small></div>
        <div class="field"><label for="customer-email">Correo electrónico</label><input id="customer-email" name="email" type="email" autocomplete="email" value="${user?.email || ""}" required /><small class="field-error" data-error-for="email"></small></div>
        <div class="field"><label for="customer-phone">Teléfono</label><input id="customer-phone" name="phone" type="tel" autocomplete="tel" required /><small class="field-error" data-error-for="phone"></small></div>
        <div class="field"><label for="customer-postal">Código postal</label><input id="customer-postal" name="postalCode" autocomplete="postal-code" required /><small class="field-error" data-error-for="postalCode"></small></div>
        <div class="field wide"><label for="customer-address">Dirección de entrega</label><input id="customer-address" name="address" autocomplete="street-address" required /><small class="field-error" data-error-for="address"></small></div>
        <div class="field"><label for="customer-city">Ciudad / colonia</label><input id="customer-city" name="city" autocomplete="address-level2" required /><small class="field-error" data-error-for="city"></small></div>
        <div class="field"><label for="payment">Método de pago (simulado)</label><select id="payment" name="paymentMethod"><option value="card">Tarjeta al recibir</option><option value="cash">Efectivo al recibir</option></select></div>
        <div class="wide"><button class="button" type="submit">Confirmar pedido · ${formatPrice(subtotal + shipping)}</button><p class="muted" style="margin:10px 0 0;font-size:.8rem">Pago de demostración: no se realizará ningún cargo.</p></div>
      </form></section>
      <aside class="summary-card"><h2>Resumen</h2>${cart.map(item => `<div class="summary-row"><span>${item.quantity} × ${item.name}</span><span>${formatPrice(item.price * item.quantity)}</span></div>`).join("")}
        <div class="summary-row"><span>Subtotal</span><span>${formatPrice(subtotal)}</span></div><div class="summary-row"><span>Envío</span><span>${shipping ? formatPrice(shipping) : "Gratis"}</span></div><div class="summary-row summary-total"><span>Total</span><span>${formatPrice(subtotal + shipping)}</span></div>
        ${subtotal < 50 ? `<p class="muted" style="font-size:.8rem">Envío gratis en pedidos desde ${formatPrice(50)}.</p>` : ""}
      </aside>
    </div></main>`;
}

export function bindCheckout() {
  document.querySelectorAll("[data-checkout-quantity]").forEach(button => button.addEventListener("click", async () => {
    const item = getState().cart.find(entry => String(entry.productId) === button.dataset.checkoutQuantity);
    if (item) await updateItemQuantity(item.productId, item.quantity + Number(button.dataset.delta));
  }));
  document.querySelectorAll("[data-remove-item]").forEach(button => button.addEventListener("click", async () => {
    await removeItem(button.dataset.removeItem);
  }));
  document.querySelector("#checkout-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const { values, errors } = validateForm(form, {
      name: { required: true, min: 2 }, email: { required: true, email: true },
      phone: { required: true, min: 7 }, postalCode: { required: true, min: 4 },
      address: { required: true, min: 5 }, city: { required: true, min: 2 }
    });
    showFieldErrors(form, errors);
    if (Object.keys(errors).length) return;
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    button.textContent = "Confirmando tu pedido…";
    try {
      const { paymentMethod, ...customer } = values;
      const order = await createOrder({ customer, paymentMethod });
      await clearCart();
      location.hash = `#/order-confirmation/${encodeURIComponent(order.id)}`;
    } catch (error) {
      document.querySelector("#checkout-status").innerHTML = `<p class="form-status" role="alert">${error.message}</p>`;
      showToast(error.message, "error");
      button.disabled = false;
      button.textContent = "Confirmar pedido";
    }
  });
}
