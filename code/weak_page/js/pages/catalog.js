import { getProducts, getLastSearchInfo } from "../services/productService.js";
import { addItem } from "../state/store.js";
import { productCard } from "../components/productCard.js";
import { loader } from "../components/loader.js";
import { emptyState } from "../components/emptyState.js";

function productGrid(products) {
  const host = document.querySelector("#catalog-results");
  if (!host) return;
  host.innerHTML = products.length
    ? `<div class="product-grid">${products.map(productCard).join("")}</div>`
    : emptyState({
        icon: "🍰",
        title: "No encontramos ese antojo",
        message: "Prueba con otra búsqueda o categoría."
      });
}

export async function renderCatalog() {
  return `<main><section class="container">
    <header class="page-intro"><span class="eyebrow">Un detalle hecho a mano</span><h1>Nuestro catálogo</h1><p class="muted">Encuentra tu próximo favorito entre nuestras delicias artesanales.</p></header>
    <div class="filters">
      <div class="field search-field"><label for="catalog-search">Buscar</label><input id="catalog-search" type="search" placeholder="Tarta, chocolate, vainilla…" /></div>
      <div class="field"><label for="catalog-category">Categoría</label><select id="catalog-category"><option value="all">Todas</option><option>Tartas</option><option>Bollería</option><option>Galletas</option></select></div>
      <div class="field"><label for="catalog-sort">Ordenar por</label><select id="catalog-sort"><option value="featured">Destacados</option><option value="price-asc">Menor precio</option><option value="price-desc">Mayor precio</option><option value="name">Nombre</option></select></div>
    </div>
    <!-- ▼▼ I4: contenedor del "eco" de la búsqueda ▼▼ -->
    <div id="search-info" class="search-info" aria-live="polite"></div>
    <!-- ▲▲ I4 ▲▲ -->
    <div id="catalog-results">${loader("Buscando algo delicioso…")}</div>
  </section></main>`;
}

export async function bindCatalog() {
  const params = new URLSearchParams(location.hash.split("?")[1] || "");

  // Lee también ?q= de la URL para que el enlace sea compartible (vector realista de I4)
  const initialQuery = params.get("q");
  if (initialQuery) document.querySelector("#catalog-search").value = initialQuery;

  const initialCategory = params.get("category");
  if (initialCategory) document.querySelector("#catalog-category").value = initialCategory;

  const refresh = async () => {
    const host = document.querySelector("#catalog-results");
    const infoHost = document.querySelector("#search-info");
    if (!host) return;
    host.innerHTML = loader();
    if (infoHost) infoHost.innerHTML = "";

    try {
      const products = await getProducts({
        query: document.querySelector("#catalog-search").value.trim(),
        category: document.querySelector("#catalog-category").value,
        sort: document.querySelector("#catalog-sort").value
      });

      productGrid(products);

      // ▼▼▼ I4 — SINK XSS REFLEJADO ▼▼▼
      // El backend (modo vulnerable) devuelve searchInfo.rendered SIN escapar.
      // Al insertarlo con innerHTML, se ejecuta cualquier HTML/JS inyectado.
      //
      // Mitigación en el backend: XSS_REFLECTED_SEARCH=false → escapeHtml en
      // el servidor. Así demostramos que aunque el frontend sea inseguro,
      // la defensa en profundidad del backend bloquea el XSS.
      const info = getLastSearchInfo();
      if (infoHost && info?.rendered) {
        infoHost.innerHTML = info.rendered;        // ❌ sink vulnerable
        // infoHost.textContent = info.raw;         // ✅ sink seguro (alternativa didáctica)
      }
    } catch (error) {
      host.innerHTML = emptyState({
        icon: "⚠️",
        title: "No pudimos cargar el catálogo",
        message: error.message,
        action: '<button class="button button-outline" id="retry-catalog">Intentar de nuevo</button>'
      });
      host.querySelector("#retry-catalog")?.addEventListener("click", refresh);
    }
  };

  let searchTimer;
  document.querySelector("#catalog-search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(refresh, 180);
  });
  document.querySelector("#catalog-category").addEventListener("change", refresh);
  document.querySelector("#catalog-sort").addEventListener("change", refresh);

  // Primera carga: si venimos con ?q= en la URL, disparamos ya
  await refresh();
}