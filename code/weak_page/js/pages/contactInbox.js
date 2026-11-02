import { request } from "../services/apiClient.js";

export function renderContactInbox() {
  return `<main class="container">
    <header class="page-intro">
      <span class="eyebrow">Laboratorio</span>
      <h1>Bandeja de contacto</h1>
      <p class="muted">Vista de administración para demostrar el XSS almacenado del laboratorio.</p>
    </header>
    <section id="contact-inbox-items" class="form-card" aria-live="polite">Cargando mensajes…</section>
  </main>`;
}

export async function bindContactInbox() {
  const host = document.querySelector("#contact-inbox-items");
  if (!host) return;

  try {
    const params = new URLSearchParams(location.hash.split("?")[1] || "");
    const probeId = params.get("probeId");
    const marker = params.get("marker");
    const result = probeId && marker
      ? await request(
        `/contact/xss-inbox/${encodeURIComponent(probeId)}?marker=${encodeURIComponent(marker)}`
      )
      : await request("/contact");
    const messages = result?.item
      ? [result.item]
      : Array.isArray(result?.items)
        ? result.items
        : [];
    host.innerHTML = messages.length
      ? messages.map((message) => `
        <article class="contact-message">
          <h2>${message.subject || "Sin asunto"}</h2>
          <p><strong>${message.name || ""}</strong> · ${message.email || ""}</p>
          <p>${message.message || ""}</p>
          <small>${message.created_at || ""}</small>
        </article>
      `).join("")
      : "<p>No hay mensajes todavía.</p>";
  } catch (error) {
    host.textContent = error.message;
  }
}
