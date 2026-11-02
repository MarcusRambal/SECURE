import { CONFIG } from "../config.js";
import { initialContactMessages } from "../data/mockData.js";
import { request } from "./apiClient.js";

const KEY = "dulceNube_contact_messages";
const delay = () => new Promise((resolve) => setTimeout(resolve, 350));

export async function sendContactMessage(data) {
  if (CONFIG.API_MODE === "api") {
    const result = await request("/contact", { method: "POST", body: data });
    // En modo vulnerable el backend puede devolver "echo" con el mensaje crudo.
    // Si la vista lo inserta con innerHTML, dispara XSS almacenado (I5).
    return result;
  }
  await delay();
  const message = { ...data, id: `msg-${Date.now()}`, createdAt: new Date().toISOString() };
  const messages = JSON.parse(localStorage.getItem(KEY) || "null") || initialContactMessages;
  localStorage.setItem(KEY, JSON.stringify([message, ...messages]));
  return { ok: true, id: message.id, echo: message };
}