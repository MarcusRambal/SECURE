import { getProduct, getRelatedProducts } from "../services/productService.js";
import { addItem } from "../state/store.js";
import { productCard } from "../components/productCard.js";
import { formatPrice } from "../utils/format.js";
import { emptyState } from "../components/emptyState.js";
import { showToast } from "../components/toast.js";

export async function renderProductDetail(id) {
  const product = await getProduct(id);
  const related = await getRelatedProducts(id);
  return `<main class="container">
    <div class="product-detail">
      <div class="detail-image"><img src="${product.image}" alt="${product.name}" /></div>
      <div class="detail-copy">
        <span class="eyebrow">${product.category} · Hecho artesanalmente</span><h1>${product.name}</h1>
        <p class="muted">${product.description}</p><p class="detail-price">${formatPrice(product.price)}</p>
        <p>${product.stock > 0 ? `Disponibles hoy: ${product.stock}` : "Agotado por hoy"}</p>
        <div class="detail-meta"><div><h3>Ingredientes</h3><p>${product.ingredients.join(", ")}</p></div><div><h3>Alérgenos</h3><p>${product.allergens.join(", ")}</p></div></div>
        <div class="quantity-control"><button type="button" id="qty-minus" aria-label="Restar uno">−</button><span id="quantity" data-stock="${product.stock}">1</span><button type="button" id="qty-plus" aria-label="Sumar uno">+</button></div>
        <button class="button" id="detail-add" type="button" ${product.stock ? "" : "disabled"}>Añadir al carrito</button>
      </div>
    </div>
    <section class="related"><div class="section-heading"><span class="eyebrow">También te puede gustar</span><h2>Del mismo antojo</h2></div>${related.length ? `<div class="product-grid">${related.map(productCard).join("")}</div>` : emptyState({ title: "Pronto habrá más", message: "Estamos horneando nuevas delicias." })}</section>
    <section class="section"><div class="section-heading"><span class="eyebrow">Reseñas dulces</span><h2>Un favorito de quienes ya lo probaron</h2></div><div class="review-list"><article class="review"><span class="stars">★★★★★</span><p>“Fresco, equilibrado y precioso. Se nota que está hecho con ingredientes buenos.”</p><strong>— Sofía M.</strong></article><article class="review"><span class="stars">★★★★★</span><p>“El postre perfecto para compartir. Ya lo pedimos para nuestra próxima reunión.”</p><strong>— Pablo R.</strong></article></div></section>
  </main>`;
}

export function bindProductDetail(id) {
  let quantity = 1;
  const productId = id;
  document.querySelector("#qty-minus")?.addEventListener("click", () => {
    quantity = Math.max(1, quantity - 1);
    document.querySelector("#quantity").textContent = quantity;
  });
  document.querySelector("#qty-plus")?.addEventListener("click", () => {
    quantity = Math.min(Number(document.querySelector("#quantity").dataset.stock || 99), quantity + 1);
    document.querySelector("#quantity").textContent = quantity;
  });
  document.querySelector("#detail-add")?.addEventListener("click", async () => {
    try {
      const product = await getProduct(productId);
      await addItem(product, quantity);
      showToast(`${product.name} añadido al carrito.`);
    } catch (error) { showToast(error.message, "error"); }
  });
}
