import * as orderService from "../services/orderService.js";

const state = { user: null, cart: [], cartOpen: false };
const listeners = new Set();
export const getState = () => state;
export function subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); }
function emit() { listeners.forEach(listener => listener(state)); }

export async function initializeStore(user) {
  state.user = user;
  state.cart = await orderService.getCart();
  emit();
}
export function setUser(user) { state.user = user; emit(); }
export async function addItem(product, quantity = 1) { state.cart = await orderService.addToCart(product, quantity); emit(); }
export async function updateItemQuantity(productId, quantity) {
  state.cart = state.cart.map(item => String(item.productId) === String(productId) ? { ...item, quantity: Math.max(1, Math.min(item.stock || 99, quantity)) } : item);
  state.cart = await orderService.saveCart(state.cart);
  emit();
}
export async function removeItem(productId) { state.cart = await orderService.saveCart(state.cart.filter(item => String(item.productId) !== String(productId))); emit(); }
export async function clearCart() { state.cart = await orderService.saveCart([]); emit(); }
export function toggleCart(open = !state.cartOpen) { state.cartOpen = open; emit(); }
