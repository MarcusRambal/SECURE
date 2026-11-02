import { CONFIG } from "../config.js";
import { categories as mockCategories, products as mockProducts, testimonials } from "../data/mockData.js";
import { request } from "./apiClient.js";

const delay = () => new Promise((resolve) => setTimeout(resolve, 280));
const PRODUCT_IMAGE_FALLBACK = "https://images.unsplash.com/photo-1488477181946-6428a0291777?auto=format&fit=crop&w=900&q=82";

function normalizeProduct(product) {
  const toList = (value) => Array.isArray(value)
    ? value
    : String(value || "").split(",").map((item) => item.trim()).filter(Boolean);

  return {
    ...product,
    image: product.image || PRODUCT_IMAGE_FALLBACK,
    featured: Boolean(product.featured),
    ingredients: toList(product.ingredients),
    allergens: toList(product.allergens)
  };
}

// ── Estado del último searchInfo (para el reto I4) ──
let _lastSearchInfo = null;
export function getLastSearchInfo() {
  return _lastSearchInfo;
}

export async function getProducts({ query = "", category = "all", sort = "featured" } = {}) {
  _lastSearchInfo = null;
  let items;

  if (CONFIG.API_MODE === "api") {
    const params = new URLSearchParams();
    if (query) params.set("q", query);
    if (category !== "all") params.set("category", category);
    const result = await request(`/products${params.size ? `?${params}` : ""}`);
    if (Array.isArray(result)) {
      items = result;
    } else {
      items = result.items || [];
      _lastSearchInfo = result.searchInfo || null;
    }
  } else {
    await delay();
    items = [...mockProducts]
      .filter((p) => category === "all" || p.category === category)
      .filter((p) => !query || `${p.name} ${p.description}`.toLowerCase().includes(query.toLowerCase()));
  }

  const sorted = items.map(normalizeProduct);
  if (sort === "price-asc")  sorted.sort((a, b) => a.price - b.price);
  if (sort === "price-desc") sorted.sort((a, b) => b.price - a.price);
  if (sort === "name")       sorted.sort((a, b) => a.name.localeCompare(b.name, "es"));
  if (sort === "featured")   sorted.sort((a, b) => Number(b.featured) - Number(a.featured));
  return sorted;
}

export async function getProduct(id) {
  if (CONFIG.API_MODE === "api") return normalizeProduct(await request(`/products/${encodeURIComponent(id)}`));
  await delay();
  const product = mockProducts.find((p) => p.id === id);
  if (!product) throw new Error("No encontramos ese producto.");
  return product;
}

export async function getFeaturedProducts() {
  if (CONFIG.API_MODE === "api") {
    const result = await request("/products?featured=true");
    const items = Array.isArray(result) ? result : result.items || [];
    return items.slice(0, 4).map(normalizeProduct);
  }
  await delay();
  return mockProducts.filter((p) => p.featured).slice(0, 4);
}

export async function getCategories() {
  if (CONFIG.API_MODE === "api") {
    const result = await request("/products/categories");
    return Array.isArray(result) ? result : result.categories || [];
  }
  await delay();
  return [...mockCategories];
}

export async function getTestimonials() {
  await delay();
  return [...testimonials];
}

export async function getRelatedProducts(id) {
  if (CONFIG.API_MODE === "api") {
    const result = await request(`/products/${encodeURIComponent(id)}/related`);
    const items = Array.isArray(result) ? result : result.items || [];
    return items.map(normalizeProduct);
  }
  await delay();
  const current = mockProducts.find((p) => p.id === id);
  return current
    ? mockProducts
        .filter((p) => p.id !== id && p.category === current.category)
        .slice(0, 4)
    : [];
}