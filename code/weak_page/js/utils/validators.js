export const isValidEmail = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
export const isRequired = value => String(value ?? "").trim().length > 0;
export const minLength = (value, min) => String(value ?? "").trim().length >= min;

export function validateForm(form, rules) {
  const values = Object.fromEntries(new FormData(form).entries());
  const errors = {};
  for (const [field, checks] of Object.entries(rules)) {
    for (const [rule, arg] of Object.entries(checks)) {
      const value = values[field] ?? "";
      const failed = rule === "required" ? !isRequired(value)
        : rule === "email" ? !isValidEmail(value)
          : rule === "min" ? !minLength(value, arg)
            : false;
      if (failed) {
        errors[field] = rule === "required" ? "Este campo es obligatorio."
          : rule === "email" ? "Escribe un correo válido."
            : `Escribe al menos ${arg} caracteres.`;
        break;
      }
    }
  }
  return { values, errors };
}

export function showFieldErrors(form, errors) {
  form.querySelectorAll("[data-error-for]").forEach(node => { node.textContent = ""; });
  Object.entries(errors).forEach(([name, message]) => {
    const node = form.querySelector(`[data-error-for="${name}"]`);
    if (node) node.textContent = message;
  });
}
