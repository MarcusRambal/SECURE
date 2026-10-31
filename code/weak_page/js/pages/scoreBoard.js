import {
  getVulnerabilities,
  toggleVulnerability,
  setAllVulnerabilities
} from "../services/adminService.js";
import { loader } from "../components/loader.js";
import { emptyState } from "../components/emptyState.js";

// ── Metadatos de los 20 retos ──────────────────────────────
const META = {
  // 💉 Injection
  SQLI_LOGIN:                { cat: "Injection", icon: "💉", name: "SQLi Login",            desc: "Bypass del login con ' OR 1=1 --" },
  SQLI_SEARCH:               { cat: "Injection", icon: "💉", name: "SQLi Búsqueda",         desc: "Inyección en ?q= del catálogo" },
  UNION_SQLI_DUMP:           { cat: "Injection", icon: "💉", name: "UNION Dump",            desc: "Volcado de tablas vía ?category=" },
  XSS_REFLECTED_SEARCH:      { cat: "Injection", icon: "💉", name: "XSS Reflejado",         desc: "HTML crudo en searchInfo.rendered" },
  XSS_STORED_CONTACT:        { cat: "Injection", icon: "💉", name: "XSS Almacenado",        desc: "HTML crudo en la bandeja de contacto" },
  // 🔐 Crypto
  PLAINTEXT_PASSWORDS:       { cat: "Crypto",    icon: "🔐", name: "Contraseñas en claro",  desc: "Nuevos registros en texto plano" },
  WEAK_MD5_LEGACY:           { cat: "Crypto",    icon: "🔐", name: "MD5 legacy",            desc: "Usuarios seed con MD5 crackeable" },
  PREDICTABLE_RESET_TOKEN:   { cat: "Crypto",    icon: "🔐", name: "Reset predecible",      desc: "Token de reset = md5(email)" },
  BASE64_FAKE_ENCRYPTION:    { cat: "Crypto",    icon: "🔐", name: "Base64 fake crypto",    desc: "PII en base64 en vez de AES-GCM" },
  HARDCODED_CRYPTO_SECRET:   { cat: "Crypto",    icon: "🔐", name: "Clave hardcodeada",     desc: "Secreto expuesto en /api/health" },
  // 🚪 Broken Access Control
  IDOR_ORDERS:               { cat: "BAC",       icon: "🚪", name: "IDOR pedidos",          desc: "Cualquiera ve pedidos ajenos" },
  MISSING_AUTH_ME:           { cat: "BAC",       icon: "🚪", name: "Auth ausente",          desc: "/me y /orders aceptan sin token" },
  EXPOSED_SENSITIVE_FILES:   { cat: "BAC",       icon: "🚪", name: "Archivos expuestos",    desc: ".env, backup.sql, logs accesibles" },
  MISSING_ROLE_CHECK_ADMIN:  { cat: "BAC",       icon: "🚪", name: "Sin rol admin",         desc: "Cualquier autenticado ve /admin/*" },
  MASS_ASSIGNMENT_REGISTER:  { cat: "BAC",       icon: "🚪", name: "Mass assignment",       desc: 'Registro acepta role:"admin"' },
  // 🔑 Authentication
  JWT_ALG_NONE:              { cat: "Auth",      icon: "🔑", name: "JWT alg:none",          desc: "Acepta tokens sin firma" },
  JWT_WEAK_SECRET:           { cat: "Auth",      icon: "🔑", name: "JWT weak secret",       desc: 'Firma con el secreto "secret"' },
  JWT_NO_EXPIRY:             { cat: "Auth",      icon: "🔑", name: "JWT sin expiry",        desc: "Tokens que nunca caducan" },
  USER_ENUMERATION:          { cat: "Auth",      icon: "🔑", name: "Enumeración usuarios",  desc: "Login distingue existente/inexistente" },
  WEAK_PASSWORD_NO_RATELIMIT:{ cat: "Auth",      icon: "🔑", name: "Password débil",        desc: "Sin política ni rate limit" }
};

const CATEGORIES = [
  { id: "Injection", label: "💉 Injection",        color: "#ef4444" },
  { id: "Crypto",    label: "🔐 Crypto Failures",  color: "#845ec2" },
  { id: "BAC",       label: "🚪 Broken Access",    color: "#ff9f1c" },
  { id: "Auth",      label: "🔑 Auth Failures",    color: "#00b4d8" }
];

// ── Flash messages (self-contained, sin dependencias) ──────
function flash(msg, type = "info") {
  const el = document.createElement("div");
  el.className = `scoreboard-flash scoreboard-flash-${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 300);
  }, 2200);
}

// ── Render helpers ─────────────────────────────────────────
function vulnCard(flag, meta, isActive) {
  return `
    <button class="vuln-card ${isActive ? "on" : "off"}" data-flag="${flag}" type="button">
      <div class="vuln-head">
        <span class="vuln-icon">${meta.icon}</span>
        <span class="vuln-status">${isActive ? "VULNERABLE" : "SEGURO"}</span>
      </div>
      <div class="vuln-name">${meta.name}</div>
      <div class="vuln-desc">${meta.desc}</div>
      <code class="vuln-flag">${flag}</code>
    </button>
  `;
}

function renderGrid(flags) {
  return CATEGORIES.map((cat) => {
    const items = Object.keys(META).filter((k) => META[k].cat === cat.id);
    const active = items.filter((f) => flags[f]).length;
    return `
      <section class="vuln-category" style="--cat-color:${cat.color}">
        <h3>${cat.label} <small>(${active}/${items.length} activas)</small></h3>
        <div class="vuln-grid">
          ${items.map((f) => vulnCard(f, META[f], flags[f])).join("")}
        </div>
      </section>
    `;
  }).join("");
}

function renderBanner(mode) {
  if (mode !== "secure") return "";
  return `<div class="scoreboard-banner">
    ⚠️ El servidor corre con <code>SECURITY_MODE=secure</code>.
    Los toggles no tendrán efecto hasta que cambies el <code>.env</code> y reinicies.
  </div>`;
}

function renderMaster(allVulnerable) {
  return `
    <div class="master-toggle">
      <button id="master-toggle" class="button ${allVulnerable ? "button-danger" : "button-success"} button-large" type="button">
        ${allVulnerable
          ? "🔒 Activar modo seguro (mitigar TODO)"
          : "⚠️ Activar modo vulnerable (activar TODO)"}
      </button>
      <p class="muted small">
        ${allVulnerable
          ? "Ahora mismo los 20 retos están ACTIVOS."
          : "Ahora mismo los 20 retos están MITIGADOS."}
      </p>
    </div>
  `;
}

// ── Página ─────────────────────────────────────────────────
export async function renderScoreboard() {
  return `<main><section class="container">
    <header class="page-intro">
      <span class="eyebrow">Laboratorio</span>
      <h1>Panel de vulnerabilidades</h1>
      <p class="muted">Activa o desactiva cada reto del lab en tiempo real. Los cambios se aplican al instante en el backend.</p>
    </header>
    <div id="scoreboard-body">${loader("Cargando estado…")}</div>
  </section></main>`;
}

export async function bindScoreboard() {
  const host = document.querySelector("#scoreboard-body");
  if (!host) return;

  let currentFlags = {};

  // Repinta la rejilla completa (usado tras el master toggle)
  const paintAll = (data) => {
    currentFlags = data.flags;
    const allVulnerable = Object.values(currentFlags).every((v) => v === true);
    host.innerHTML = `
      ${renderBanner(data.securityMode)}
      ${renderMaster(allVulnerable)}
      ${renderGrid(currentFlags)}
    `;
    attachMaster();
    attachCards();
  };

  // Actualiza la tarjeta tocada sin repintar todo
  const paintCard = (btn, flag, isActive) => {
    btn.classList.toggle("on", isActive);
    btn.classList.toggle("off", !isActive);
    btn.querySelector(".vuln-status").textContent = isActive ? "VULNERABLE" : "SEGURO";

    // Actualiza el contador de la categoría
    const cat = META[flag].cat;
    const catItems = Object.keys(META).filter((k) => META[k].cat === cat);
    const small = btn.closest(".vuln-category").querySelector("h3 small");
    if (small) {
      const activeCount = catItems.filter((f) => currentFlags[f]).length;
      small.textContent = `(${activeCount}/${catItems.length} activas)`;
    }

    // Actualiza el botón maestro
    const allVulnerable = Object.values(currentFlags).every((v) => v === true);
    const master = document.querySelector("#master-toggle");
    if (master) {
      master.textContent = allVulnerable
        ? "🔒 Activar modo seguro (mitigar TODO)"
        : "⚠️ Activar modo vulnerable (activar TODO)";
      master.classList.toggle("button-danger", allVulnerable);
      master.classList.toggle("button-success", !allVulnerable);
    }
  };

  const refresh = async () => {
    host.innerHTML = loader("Cargando estado…");
    try {
      const data = await getVulnerabilities();
      paintAll(data);
    } catch (err) {
      host.innerHTML = emptyState({
        icon: "🔐",
        title: "No podemos acceder al panel",
        message: `${err.message}. Inicia sesión como admin@dulcenube.com / admin123, o reinicia el backend si te has bloqueado.`,
        action: `<a href="#/login" class="button">Ir a login</a>`
      });
    }
  };

  const attachMaster = () => {
    document.querySelector("#master-toggle")?.addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      const target = !Object.values(currentFlags).every((v) => v === true); // si todo vulnerable → false
      try {
        const data = await setAllVulnerabilities(target);
        paintAll(data);
        flash(target ? "⚠️ TODAS las vulnerabilidades ACTIVADAS" : "🔒 TODAS las vulnerabilidades MITIGADAS", target ? "warn" : "success");
      } catch (err) {
        flash(`Error: ${err.message}`, "error");
        btn.disabled = false;
      }
    });
  };

  const attachCards = () => {
    host.querySelectorAll(".vuln-card").forEach((card) => {
      card.addEventListener("click", async (e) => {
        const btn = e.currentTarget;
        const flag = btn.dataset.flag;
        const prev = currentFlags[flag];
        btn.disabled = true;
        try {
          const data = await toggleVulnerability(flag, !prev);
          currentFlags = data.flags;
          paintCard(btn, flag, currentFlags[flag]);
          flash(`${flag}: ${currentFlags[flag] ? "ACTIVADA" : "MITIGADA"}`, currentFlags[flag] ? "warn" : "success");
        } catch (err) {
          flash(`Error: ${err.message}`, "error");
        } finally {
          btn.disabled = false;
        }
      });
    });
  };

  await refresh();
}