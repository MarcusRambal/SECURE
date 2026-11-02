import { register } from "../services/authService.js";
import { setUser } from "../state/store.js";
import { showToast } from "../components/toast.js";
import { validateForm, showFieldErrors } from "../utils/validators.js";

export function renderRegister() {
  return `<main class="auth-wrap"><section class="auth-card">
    <span class="eyebrow">Forma parte de la familia</span><h1>Crear cuenta</h1><p class="muted">Guarda tus datos y celebra cada antojo.</p>
    <div id="register-status" aria-live="polite"></div>
    <form id="register-form" novalidate>
      <div class="field"><label for="name">Nombre completo</label><input id="name" name="name" autocomplete="name" required /><small class="field-error" data-error-for="name"></small></div>
      <div class="field"><label for="email">Correo electrónico</label><input id="email" name="email" type="email" autocomplete="email" required /><small class="field-error" data-error-for="email"></small></div>
      <div class="field"><label for="password">Contraseña (mínimo 6 caracteres)</label><input id="password" name="password" type="password" autocomplete="new-password" required /><small class="field-error" data-error-for="password"></small></div>
      <button class="button" type="submit">Crear mi cuenta</button>
    </form>
    <p class="muted">¿Ya tienes una cuenta? <a class="text-link" href="#/login">Inicia sesión</a></p>
  </section></main>`;
}

export function bindRegister() {
  document.querySelector("#register-form")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const { values, errors } = validateForm(form, { name: { required: true, min: 2 }, email: { required: true, email: true }, password: { required: true, min: 6 } });
    showFieldErrors(form, errors);
    if (Object.keys(errors).length) return;
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    button.textContent = "Creando cuenta…";
    try {
      const user = await register(values);
      setUser(user);
      showToast("Tu cuenta está lista. ¡Bienvenida!", "success");
      location.hash = "#/catalog";
    } catch (error) {
      document.querySelector("#register-status").innerHTML = `<p class="form-status" role="alert">${error.message}</p>`;
    } finally {
      button.disabled = false;
      button.textContent = "Crear mi cuenta";
    }
  });
}
