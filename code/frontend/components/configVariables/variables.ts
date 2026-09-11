// Opciones de categorías de ataque y sus ataques específicos asociados
export const ATTACK_CATEGORIES = {
  injection: {
    label: "Injection",
    attacks: [{ id: "sqli", label: "SQL Injection" }],
  },
  broken_access: {
    label: "Broken Access Control",
    attacks: [{ id: "bac_default", label: "Proximamente / General" }],
  },
  auth_failure: {
    label: "Authentication Failure",
    attacks: [{ id: "auth_default", label: "Proximamente / General" }],
  },
  crypto_failure: {
    label: "Cryptographic Failures",
    attacks: [{ id: "crypto_default", label: "Proximamente / General" }],
  },
};

// Modelos LLM disponibles para la selección
export const AVAILABLE_LLM_MODELS = [
  "GPT-4o (OpenAI)",
  "GPT-4o-mini (OpenAI)",
  "Claude 3.5 Sonnet (Anthropic)",
  "Llama 3.3 70B (Ollama / Local)",
  "DeepSeek-R1",
];
