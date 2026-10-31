import { formatPrice } from "../utils/format.js";

export function productCard(product) {
  return `<article class="product-card">
    <a class="product-image-wrap" href="#/product/${encodeURIComponent(product.id)}" aria-label="Ver ${product.name}">
      <img class="product-image" src="${product.image}" alt="${product.name}" loading="lazy" />
      ${product.featured ? '<span class="badge">Favorito</span>' : ""}
    </a>
    <div class="product-info">
      <p class="product-category">${product.category}</p>
      <h3><a href="#/product/${encodeURIComponent(product.id)}">${product.name}</a></h3>
      <p class="muted">${product.description.slice(0, 68)}${product.description.length > 68 ? "…" : ""}</p>
      <div class="product-bottom"><span class="price">${formatPrice(product.price)}</span>
        <button class="add-button" type="button" data-add-product="${product.id}" aria-label="Añadir ${product.name} al carrito">+</button>
      </div>
    </div>
  </article>`;
}
