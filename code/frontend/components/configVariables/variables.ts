// Opciones de categorías de ataque y sus ataques específicos asociados
export const ATTACK_CATEGORIES = {
  injection: {
    label: "Injeccion",
    attacks: [
      { id: "sqli", label: "Inyeccion SQL" },
      { id: "xss", label: "XSS" },
    ],
  },
  crypto_failure: {
    label: "Fallos criptograficos",
    attacks: [{ id: "crypto_default", label: "Proximamente / General" }],
  },
  broken_access: {
    label: "Acceso Roto",
    attacks: [{ id: "bac_default", label: "Proximamente / General" }],
  },
  auth_failure: {
    label: "Fallos de autenticacion",
    attacks: [{ id: "auth_default", label: "Proximamente / General" }],
  },
};
