import { getState, toggleCart, setUser } from "../state/store.js";
import { logout } from "../services/authService.js";
import { showToast } from "./toast.js";

export function renderHeader(active = "") {
  const { user, cart } = getState();
  const count = cart.reduce((sum, item) => sum + item.quantity, 0);
  return `<header class="site-header"><div class="container header-inner">
    <a href="#/home" class="brand" aria-label="Dulce Nube, inicio"><span class="brand-mark">☁</span><span>Dulce Nube</span></a>
    <nav class="main-nav" id="main-nav" aria-label="Navegación principal">
      <a class="${active === "home" ? "active" : ""}" href="#/home">Inicio</a>
      <a class="${active === "catalog" ? "active" : ""}" href="#/catalog">Catálogo</a>
      <a class="${active === "about" ? "active" : ""}" href="#/about">Nosotras</a>
      <a class="${active === "contact" ? "active" : ""}" href="#/contact">Contacto</a>
      <a class="nav-link nav-lab ${active === "scoreboard" ? "active" : ""}" href="#/scoreboard" title="Panel de vulnerabilidades">🧪 Lab</a>
      ${user ? "" : '<a href="#/register">Crear cuenta</a>'}
    </nav>
    <div class="header-actions">
      ${user ? `<div class="nav-user"><span class="muted">Hola, ${user.name.split(" ")[0]}</span><button class="nav-action" id="logout-button" type="button">Salir</button></div>` : `<a class="button button-small" href="#/login">Entrar</a>`}
      <button class="icon-button" id="cart-button" type="button" aria-label="Abrir carrito">♡<span class="cart-count">${count}</span></button>
      <button class="icon-button menu-toggle" id="menu-button" type="button" aria-label="Abrir menú" aria-expanded="false">☰</button>
    </div>
  </div></header>`;
}

export function bindHeader() {
  document.querySelector("#cart-button")?.addEventListener("click", () => toggleCart(true));
  const menuButton = document.querySelector("#menu-button");
  menuButton?.addEventListener("click", () => {
    const nav = document.querySelector("#main-nav");
    const open = nav.classList.toggle("open");
    menuButton.setAttribute("aria-expanded", String(open));
    menuButton.setAttribute("aria-label", open ? "Cerrar menú" : "Abrir menú");
  });
  document.querySelectorAll("#main-nav a").forEach(link => link.addEventListener("click", () => document.querySelector("#main-nav")?.classList.remove("open")));
  document.querySelector("#logout-button")?.addEventListener("click", async () => {
    try {
      await logout();
      setUser(null);
      location.hash = "#/home";
    } catch (error) {
      showToast(error.message, "error");
    }
  });
}
