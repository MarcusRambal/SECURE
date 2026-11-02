import { CONFIG } from "../config.js";
import { users as mockUsers } from "../data/mockData.js";
import { request } from "./apiClient.js";

const USERS_KEY = "dulceNube_users";
const SESSION_KEY = "dulceNube_session";
const delay = () => new Promise(resolve => setTimeout(resolve, 350));
const safeUser = ({ password, ...user }) => user;
const getUsers = () => JSON.parse(localStorage.getItem(USERS_KEY) || "null") || mockUsers;

export async function login({ email, password }) {
  if (CONFIG.API_MODE === "api") {
    const result = await request("/auth/login", { method: "POST", body: { email, password } });
    const session = { user: result.user, token: result.token };
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    return result.user;
  }
  await delay();
  const user = getUsers().find(item => item.email.toLowerCase() === email.toLowerCase() && item.password === password);
  if (!user) throw new Error("Correo o contraseña incorrectos.");
  localStorage.setItem(SESSION_KEY, JSON.stringify({ user: safeUser(user) }));
  return safeUser(user);
}

export async function register({ name, email, password }) {
  if (CONFIG.API_MODE === "api") {
    const result = await request("/auth/register", { method: "POST", body: { name, email, password } });
    localStorage.setItem(SESSION_KEY, JSON.stringify({ user: result.user, token: result.token }));
    return result.user;
  }
  await delay();
  const current = getUsers();
  if (current.some(user => user.email.toLowerCase() === email.toLowerCase())) throw new Error("Ya existe una cuenta con ese correo.");
  const user = { id: `user-${Date.now()}`, name, email, password, createdAt: new Date().toISOString() };
  localStorage.setItem(USERS_KEY, JSON.stringify([...current, user]));
  localStorage.setItem(SESSION_KEY, JSON.stringify({ user: safeUser(user) }));
  return safeUser(user);
}

export async function getSession() {
  if (CONFIG.API_MODE === "api") {
    const stored = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    if (!stored?.token) return null;
    try {
      const result = await request("/me", { token: stored.token });
      // El backend devuelve { user } en /me (B2 vulnerable devuelve _vulnerable)
      return result.user || result;
    } catch {
      // Token inválido / expirado → limpiamos y tratamos como no logueado
      localStorage.removeItem(SESSION_KEY);
      return null;
    }
  }
  await delay();
  return JSON.parse(localStorage.getItem(SESSION_KEY) || "null")?.user || null;
}

export async function logout() {
  const stored = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
  if (CONFIG.API_MODE === "api" && stored?.token) await request("/auth/logout", { method: "POST", token: stored.token });
  localStorage.removeItem(SESSION_KEY);
}
