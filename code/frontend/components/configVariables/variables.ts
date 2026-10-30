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
    label: "Fallos criptográficos",
    attacks: [{ id: "crypto_inspector", label: "Crypto Inspector" }],
  },
  broken_access: {
    label: "Acceso Roto",
    attacks: [{ id: "bac_default", label: "Proximamente / General" }],
  },
  auth_failure: {
    label: "Authentication Failure",
    attacks: [
      { id: "jwt", label: "JWT Analysis" },
      { id: "auth_default", label: "Proximamente / General" },
    ],
  },
};
