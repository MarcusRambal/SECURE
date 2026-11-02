import { CONFIG } from "../config.js";
import { initialOrders } from "../data/mockData.js";
import { request } from "./apiClient.js";

const CART_KEY   = "dulceNube_cart";
const ORDERS_KEY = "dulceNube_orders";
const delay = () => new Promise((resolve) => setTimeout(resolve, 350));

const getOrders = () => JSON.parse(localStorage.getItem(ORDERS_KEY) || "null") || initialOrders;
const getToken  = () => JSON.parse(localStorage.getItem("dulceNube_session") || "null")?.token || null;

function normalizeOrder(order) {
  return {
    ...order,
    id: order.code || String(order.id),
    numericId: order.id,
    createdAt: order.createdAt || order.created_at,
    paymentMethod: order.paymentMethod || order.payment_method
  };
}

export async function getCart() {
  await delay();
  return JSON.parse(localStorage.getItem(CART_KEY) || "[]");
}

export async function saveCart(cart) {
  localStorage.setItem(CART_KEY, JSON.stringify(cart));
  return cart;
}

export async function addToCart(product, quantity = 1) {
  const cart = JSON.parse(localStorage.getItem(CART_KEY) || "[]");
  const existing = cart.find((item) => String(item.productId) === String(product.id));
  if (existing) existing.quantity = Math.min(product.stock, existing.quantity + quantity);
  else cart.push({
    productId: product.id,
    name: product.name,
    price: product.price,
    image: product.image,
    stock: product.stock,
    quantity: Math.min(product.stock, quantity)
  });
  return saveCart(cart);
}

export async function createOrder({ customer, paymentMethod }) {
  const cart = JSON.parse(localStorage.getItem(CART_KEY) || "[]");
  if (!cart.length) throw new Error("Tu carrito está vacío.");

  const items = cart.map(({ productId, name, price, quantity }) => ({
    productId, name, price, quantity
  }));

  if (CONFIG.API_MODE === "api") {
    const raw = await request("/orders", {
      method: "POST",
      body: { customer, items, paymentMethod },
      token: getToken()
    });
    localStorage.setItem(CART_KEY, "[]");
    // Normalizamos: el id público es el code (DN-XXXX)
    return normalizeOrder(raw);
  }

  await delay();
  const subtotal = items.reduce((s, i) => s + i.price * i.quantity, 0);
  const shipping = subtotal >= 50 ? 0 : 5;
  const code = `DN-${Date.now().toString(36).toUpperCase()}`;
  const order = {
    id: code,
    code,
    customer,
    items,
    subtotal,
    shipping,
    total: subtotal + shipping,
    paymentMethod,
    status: "confirmado",
    createdAt: new Date().toISOString()
  };
  localStorage.setItem(ORDERS_KEY, JSON.stringify([order, ...getOrders()]));
  localStorage.setItem(CART_KEY, "[]");
  return order;
}

export async function getOrder(id) {
  if (CONFIG.API_MODE === "api") {
    return normalizeOrder(await request(`/orders/${encodeURIComponent(id)}`, { token: getToken() }));
  }
  await delay();
  const order = getOrders().find((item) => item.id === id || item.code === id);
  if (!order) throw new Error("No encontramos ese pedido.");
  return order;
}