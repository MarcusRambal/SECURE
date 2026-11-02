const routes = [
  { pattern: /^\/home\/?$/, key: "home", title: "Inicio" },
  { pattern: /^\/login\/?$/, key: "login", title: "Iniciar sesión" },
  { pattern: /^\/register\/?$/, key: "register", title: "Crear cuenta" },
  { pattern: /^\/catalog\/?$/, key: "catalog", title: "Catálogo" },
  { pattern: /^\/product\/([^/]+)\/?$/, key: "productDetail", title: "Producto" },
  { pattern: /^\/checkout\/?$/, key: "checkout", title: "Tu pedido" },
  { pattern: /^\/order-confirmation\/([^/]+)\/?$/, key: "orderConfirmation", title: "Pedido confirmado" },
  { pattern: /^\/contact\/?$/, key: "contact", title: "Contacto" },
  { pattern: /^\/contact-inbox\/?$/, key: "contactInbox", title: "Bandeja de contacto" },
  { pattern: /^\/about\/?$/, key: "about", title: "Sobre nosotras" },
  { pattern: /^\/scoreboard\/?$/, key: "scoreboard", title: "Panel de vulnerabilidades" }
];

export function resolveRoute(hash = location.hash) {
  const [path = "/home"] = hash.replace(/^#/, "").split("?");
  const normalized = path || "/home";
  for (const route of routes) {
    const match = normalized.match(route.pattern);
    if (match) return { ...route, params: match.slice(1).map(decodeURIComponent) };
  }
  return { key: "notFound", title: "Página no encontrada", params: [] };
}
