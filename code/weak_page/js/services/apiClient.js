import { CONFIG } from "../config.js";

export async function request(path, { method = "GET", body, token, headers = {} } = {}) {
  const response = await fetch(`${CONFIG.API_BASE_URL}${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  const payload = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(payload?.message || `Error de API (${response.status})`);
  return payload;
}
