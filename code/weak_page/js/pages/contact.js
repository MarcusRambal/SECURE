import { sendContactMessage } from "../services/contactService.js";
import { showToast } from "../components/toast.js";
import { validateForm, showFieldErrors } from "../utils/validators.js";

export function renderContact() {
  return `<main class="container"><header class="page-intro"><span class="eyebrow">Nos encantará leerte</span><h1>Hablemos de algo dulce</h1><p class="muted">¿Tienes una pregunta o una idea especial? Aquí estamos.</p></header>
    <div class="contact-grid"><section class="form-card"><h2>Escríbenos</h2><div id="contact-status" aria-live="polite"></div>
      <form class="form-stack" id="contact-form" novalidate>
        <div class="field"><label for="contact-name">Nombre</label><input id="contact-name" name="name" autocomplete="name" required /><small class="field-error" data-error-for="name"></small></div>
        <div class="field"><label for="contact-email">Correo electrónico</label><input id="contact-email" name="email" type="email" autocomplete="email" required /><small class="field-error" data-error-for="email"></small></div>
        <div class="field"><label for="contact-subject">Asunto</label><input id="contact-subject" name="subject" required /><small class="field-error" data-error-for="subject"></small></div>
        <div class="field"><label for="contact-message">Tu mensaje</label><textarea id="contact-message" name="message" rows="5" required></textarea><small class="field-error" data-error-for="message"></small></div>
        <button class="button" type="submit">Enviar mensaje</button>
      </form>
      <p><a href="#/contact-inbox">Abrir bandeja del laboratorio</a></p>
    </section>
    <aside class="info-card"><span class="eyebrow">Pasa a saludar</span><h2>El aroma te guía</h2>
      <div class="info-row"><strong>Dirección</strong><span>Av. de los Dulces 128, Col. Centro<br />Ciudad de México, CDMX</span></div>
      <div class="info-row"><strong>Horario</strong><span>Martes a domingo · 9:00 a 19:00<br />Lunes · Cerrado para hornear</span></div>
      <div class="info-row"><strong>Contacto</strong><span>+52 55 1234 5678<br />hola@dulcenube.com</span></div>
      <div class="map-placeholder" role="img" aria-label="Mapa ilustrativo de la ubicación"><span>📍<br />Aquí está nuestra pastelería<br /><small>(ubicación ilustrativa)</small></span></div>
    </aside></div>
  </main>`;
}

export function bindContact() {
  document.querySelector("#contact-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const { values, errors } = validateForm(form, { name: { required: true, min: 2 }, email: { required: true, email: true }, subject: { required: true, min: 3 }, message: { required: true, min: 10 } });
    showFieldErrors(form, errors);
    if (Object.keys(errors).length) return;
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    button.textContent = "Enviando…";
    try {
      await sendContactMessage(values);
      form.reset();
      document.querySelector("#contact-status").innerHTML = '<p class="form-status success" role="status">¡Mensaje enviado! Nos pondremos en contacto contigo muy pronto.</p>';
      showToast("Tu mensaje llegó a Dulce Nube.");
    } catch (error) {
      document.querySelector("#contact-status").innerHTML = `<p class="form-status" role="alert">${error.message}</p>`;
    } finally {
      button.disabled = false;
      button.textContent = "Enviar mensaje";
    }
  });
}
