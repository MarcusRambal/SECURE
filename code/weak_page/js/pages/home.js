import { getCategories, getFeaturedProducts, getTestimonials } from "../services/productService.js";
import { productCard } from "../components/productCard.js";

const categoryImages = {
  Tortas: "photo-1464305795204-6f5bbfc7fb81",
  Pasteles: "photo-1578985545062-69928b1d9587",
  Galletas: "photo-1499636136210-6f4ee915583e",
  Panadería: "photo-1555507036-ab1f4038808a"
};

export async function renderHome() {
  const [categories, products, testimonials] = await Promise.all([getCategories(), getFeaturedProducts(), getTestimonials()]);
  return `<main>
    <section class="hero"><div class="container"><div class="hero-content">
      <span class="eyebrow">Un poquito de magia, recién horneada</span>
      <h1>Hecho con amor.<br /><em>Compartido con alegría.</em></h1>
      <p>Pastelería artesanal para celebrar lo cotidiano y hacer inolvidables tus momentos especiales.</p>
      <div class="hero-actions"><a class="button" href="#/catalog">Ver catálogo <span aria-hidden="true">→</span></a><a class="button button-outline" href="#/about">Conoce nuestra historia</a></div>
      <div class="hero-note"><span>★★★★★</span> Favoritos del barrio desde 2018</div>
    </div></div></section>
    <section class="section"><div class="container">
      <div class="section-heading"><span class="eyebrow">Un antojo para cada ocasión</span><h2>¿Qué se te antoja hoy?</h2><p class="muted">Pequeñas delicias hechas a mano, con ingredientes que sí importan.</p></div>
      <div class="category-grid">${categories.map(category => `<a class="category-tile" href="#/catalog?category=${encodeURIComponent(category)}" style="background-image:linear-gradient(0deg,#3b241d9c,transparent 70%),url(https://images.unsplash.com/${categoryImages[category] || categoryImages.Tortas}?auto=format&fit=crop&w=700&q=80)"><h3>${category}</h3></a>`).join("")}</div>
    </div></section>
    <section class="section soft-section"><div class="container">
      <div class="section-heading"><span class="eyebrow">Recién salidos del horno</span><h2>Los favoritos de la casa</h2><p class="muted">Nuestros clásicos, preparados con calma y mucho cariño.</p></div>
      <div class="product-grid">${products.map(productCard).join("")}</div>
      <div class="center-action"><a class="button button-outline" href="#/catalog">Ver todos los productos</a></div>
    </div></section>
    <section class="section"><div class="container">
      <div class="section-heading"><span class="eyebrow">Palabras bonitas</span><h2>Lo que dicen nuestros clientes</h2></div>
      <div class="testimonial-grid">${testimonials.map(item => `<article class="testimonial"><div class="stars" aria-label="${item.rating} de 5 estrellas">${"★".repeat(item.rating)}</div><blockquote>“${item.text}”</blockquote><strong>${item.name}</strong><p class="muted">${item.date}</p></article>`).join("")}</div>
    </div></section>
    <section class="section"><div class="container"><div class="cta-panel"><h2>Un día especial merece algo hecho especialmente para ti.</h2><a class="button" href="#/contact">Cuéntanos tu idea <span aria-hidden="true">→</span></a></div></div></section>
  </main>`;
}

export function bindHome() {}
