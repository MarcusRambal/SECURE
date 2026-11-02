import { login } from "../services/authService.js";
import { setUser } from "../state/store.js";
import { showToast } from "../components/toast.js";
import { validateForm, showFieldErrors } from "../utils/validators.js";

export function renderLogin() {
  const redirect = new URLSearchParams(location.hash.split("?")[1] || "").get("next") || "/catalog";
  return `<main class="auth-wrap"><section class="auth-card">
    <span class="eyebrow">Qué alegría verte</span><h1>Inicia sesión</h1><p class="muted">Entra a tu cuenta para seguir endulzando tus días.</p>
    <div id="login-status" aria-live="polite"></div>
    <form id="login-form" novalidate>
      <div class="field"><label for="email">Correo electrónico</label><input id="email" name="email" type="email" autocomplete="email" required /><small class="field-error" data-error-for="email"></small></div>
      <div class="field"><label for="password">Contraseña</label><input id="password" name="password" type="password" autocomplete="current-password" required /><small class="field-error" data-error-for="password"></small></div>
      <button class="button" type="submit">Entrar a mi cuenta</button>
    </form>
    <p class="muted">¿Aún no tienes cuenta? <a class="text-link" href="#/register">Regístrate</a></p>
    <p class="demo-note"><strong>Prueba:</strong> hola@dulcenube.com / nube123<br />También: ana@dulcenube.com / ana123</p>
  </section></main>`;
}

export function bindLogin() {
  document.querySelector("#login-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const { values, errors } = validateForm(form, { email: { required: true, email: true }, password: { required: true } });
    showFieldErrors(form, errors);
    if (Object.keys(errors).length) return;
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    button.textContent = "Entrando…";
    try {
      const user = await login(values);
      setUser(user);
      showToast(`¡Hola, ${user.name.split(" ")[0]}!`, "success");
      const next = new URLSearchParams(location.hash.split("?")[1] || "").get("next") || "/catalog";
      location.hash = `#${next}`;
    } catch (error) {
      const status = document.querySelector("#login-status");
      status.innerHTML = `<p class="form-status" role="alert">${error.message}</p>`;
    } finally {
      button.disabled = false;
      button.textContent = "Entrar a mi cuenta";
    }
  });
}
