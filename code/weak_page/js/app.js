import { resolveRoute } from "./router.js";
import { getSession } from "./services/authService.js";
import { initializeStore, subscribe, getState, addItem } from "./state/store.js";
import { getProducts } from "./services/productService.js";
import { renderHeader, bindHeader } from "./components/header.js";
import { renderFooter } from "./components/footer.js";
import { renderCartDrawer, bindCartDrawer } from "./components/cartDrawer.js";
import { showToast } from "./components/toast.js";
import { loader } from "./components/loader.js";
import * as home from "./pages/home.js";
import * as login from "./pages/login.js";
import * as register from "./pages/register.js";
import * as catalog from "./pages/catalog.js";
import * as productDetail from "./pages/productDetail.js";
import * as checkout from "./pages/checkout.js";
import * as orderConfirmation from "./pages/orderConfirmation.js";
import * as contact from "./pages/contact.js";
import * as contactInbox from "./pages/contactInbox.js";
import * as about from "./pages/about.js";
import * as scoreboard from "./pages/scoreBoard.js";

import { emptyState } from "./components/emptyState.js";

const app = document.querySelector("#app");
let renderId = 0;
const pageModules = { home, login, register, catalog, productDetail, checkout, orderConfirmation, contact, contactInbox, about, scoreboard };

function renderShell() {
  const header = document.querySelector("#site-header");
  if (header) header.outerHTML = `<div id="site-header">${renderHeader(resolveRoute().key)}</div>`;
  const drawer = document.querySelector("#cart-drawer-root");
  if (drawer) drawer.outerHTML = `<div id="cart-drawer-root">${renderCartDrawer()}</div>`;
  bindHeader();
  bindCartDrawer();
}

async function renderRoute() {
  const currentRender = ++renderId;
  const route = resolveRoute();
  const page = pageModules[route.key];
  document.title = `${route.title} | Dulce Nube`;
  app.innerHTML = `<div id="site-header">${renderHeader(route.key)}</div><div id="cart-drawer-root">${renderCartDrawer()}</div><div id="page-content">${loader()}</div>${renderFooter()}`;
  bindHeader();
  bindCartDrawer();
  const content = document.querySelector("#page-content");
  try {
    let markup;
    if (route.key === "productDetail") markup = await productDetail.renderProductDetail(route.params[0]);
    else if (route.key === "orderConfirmation") markup = await orderConfirmation.renderOrderConfirmation(route.params[0]);
    else if (page) markup = await page[`render${route.key[0].toUpperCase()}${route.key.slice(1)}`]();
    else markup = `<main class="container">${emptyState({ icon: "🔎", title: "Esta página se fue de paseo", message: "No encontramos la página que buscas.", action: '<a class="button" href="#/home">Volver al inicio</a>' })}</main>`;
    if (currentRender !== renderId) return;
    content.innerHTML = markup;
    const binder = route.key === "productDetail" ? () => productDetail.bindProductDetail(route.params[0]) : page?.[`bind${route.key[0].toUpperCase()}${route.key.slice(1)}`];
    if (binder) await binder();
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (error) {
    if (currentRender !== renderId) return;
    content.innerHTML = `<main class="container">${emptyState({ icon: "⚠️", title: "Algo no salió como esperábamos", message: error.message, action: '<a class="button button-outline" href="#/home">Volver al inicio</a>' })}</main>`;
  }
}

document.addEventListener("click", async event => {
  const button = event.target.closest("[data-add-product]");
  if (!button) return;
  const originalText = button.textContent;
  button.disabled = true;
  try {
    const products = await getProducts();
    const product = products.find(item => String(item.id) === button.dataset.addProduct);
    if (product) {
      await addItem(product);
      showToast(`${product.name} añadido al carrito.`);
    }
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = originalText;
  }
});

let previousCart = "";
subscribe(state => {
  renderShell();
  const nextCart = JSON.stringify(state.cart);
  if (previousCart && nextCart !== previousCart && resolveRoute().key === "checkout") renderRoute();
  previousCart = nextCart;
});
window.addEventListener("hashchange", renderRoute);
const session = await getSession().catch(error => {
  console.error("No se pudo restaurar la sesión:", error);
  return null;
});
await initializeStore(session);
if (!location.hash) location.hash = "#/home";
else await renderRoute();
