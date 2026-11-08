import {
  getVulnerabilities,
  toggleVulnerability,
  setAllVulnerabilities
} from "../services/adminService.js";
import { loader } from "../components/loader.js";
import { emptyState } from "../components/emptyState.js";

// ── Metadatos de los 20 retos ──────────────────────────────
const META = {
  SQLI_LOGIN:                { cat: "Injection", icon: "💉", name: "SQLi Login",            desc: "Bypass del login con ' OR 1=1 --" },
  SQLI_SEARCH:               { cat: "Injection", icon: "💉", name: "SQLi Búsqueda",         desc: "Inyección en ?q= del catálogo" },
  UNION_SQLI_DUMP:           { cat: "Injection", icon: "💉", name: "UNION Dump",            desc: "Volcado de tablas vía ?category=" },
  XSS_REFLECTED_SEARCH:      { cat: "Injection", icon: "💉", name: "XSS Reflejado",         desc: "HTML crudo en searchInfo.rendered" },
  XSS_STORED_CONTACT:        { cat: "Injection", icon: "💉", name: "XSS Almacenado",        desc: "HTML crudo en la bandeja de contacto" },
  PLAINTEXT_PASSWORDS:       { cat: "Crypto",    icon: "🔐", name: "Contraseñas en claro",  desc: "Nuevos registros en texto plano" },
  WEAK_MD5_LEGACY:           { cat: "Crypto",    icon: "🔐", name: "MD5 legacy",            desc: "Usuarios seed con MD5 crackeable" },
  PREDICTABLE_RESET_TOKEN:   { cat: "Crypto",    icon: "🔐", name: "Reset predecible",      desc: "Token de reset = md5(email)" },
  BASE64_FAKE_ENCRYPTION:    { cat: "Crypto",    icon: "🔐", name: "Base64 fake crypto",    desc: "PII en base64 en vez de AES-GCM" },
  HARDCODED_CRYPTO_SECRET:   { cat: "Crypto",    icon: "🔐", name: "Clave hardcodeada",     desc: "Secreto expuesto en /api/health" },
  IDOR_ORDERS:               { cat: "BAC",       icon: "🚪", name: "IDOR pedidos",          desc: "Cualquiera ve pedidos ajenos" },
  MISSING_AUTH_ME:           { cat: "BAC",       icon: "🚪", name: "Auth ausente",          desc: "/me y /orders aceptan sin token" },
  EXPOSED_SENSITIVE_FILES:   { cat: "BAC",       icon: "🚪", name: "Archivos expuestos",    desc: ".env, backup.sql, logs accesibles" },
  MISSING_ROLE_CHECK_ADMIN:  { cat: "BAC",       icon: "🚪", name: "Sin rol admin",         desc: "Cualquier autenticado ve /admin/*" },
  MASS_ASSIGNMENT_REGISTER:  { cat: "BAC",       icon: "🚪", name: "Mass assignment",       desc: 'Registro acepta role:"admin"' },
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

// Flags cuyo cambio deja inválidos los tokens ya emitidos (firma/claims
// dependen del flag). Cuando el usuario los togglea, hay que re-loguear
// para que SECURE reciba un token acorde a la nueva configuración.
const JWT_TOKEN_REFRESH_FLAGS = new Set([
  "JWT_ALG_NONE",
  "JWT_WEAK_SECRET",
  "JWT_NO_EXPIRY",
]);
// Flags JWT ya modificados en esta sesión (para el banner persistente).
const jwtFlagsChanged = new Set();

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

function renderJwtWarning() {
  if (!jwtFlagsChanged.size) return "";
  const flags = [...jwtFlagsChanged].join(", ");
  return `<div class="scoreboard-banner scoreboard-banner-info" role="alert">
    ⚠️ Cambiaste ${jwtFlagsChanged.size} flag(s) relacionado(s) con JWT
    (<code>${flags}</code>).
    Los tokens emitidos <strong>antes</strong> del cambio siguen siendo inseguros.
    <strong>Cierra sesión y vuelve a iniciar sesión</strong> para obtener un token
    firmado con la configuración actual; si no, SECURE seguirá recibiendo un token
    viejo y reportará el hallazgo como si el flag siguiera activo.
    <button type="button" class="button button-small" id="dismiss-jwt-warning" style="margin-left:1rem">Entendido</button>
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
    <div id="scoreboard-body">
      <div id="jwt-warning-slot"></div>
      <div id="scoreboard-content">${loader("Cargando estado…")}</div>
    </div>
  </section></main>`;
}

export async function bindScoreboard() {
  const host = document.querySelector("#scoreboard-body");
  if (!host) return;
  const content = document.querySelector("#scoreboard-content");
  const warningSlot = document.querySelector("#jwt-warning-slot");
  if (!content || !warningSlot) return;

  let currentFlags = {};
  let currentSecurityMode = "vulnerable";

  const paintWarning = () => {
    warningSlot.innerHTML = renderJwtWarning();
    document.querySelector("#dismiss-jwt-warning")?.addEventListener("click", () => {
      jwtFlagsChanged.clear();
      paintWarning();
    });
  };

  const paintAll = (data) => {
    currentFlags = data.flags;
    currentSecurityMode = data.securityMode || "vulnerable";
    const allVulnerable = Object.values(currentFlags).every((v) => v === true);
    content.innerHTML = `
      ${renderBanner(currentSecurityMode)}
      ${renderMaster(allVulnerable)}
      ${renderGrid(currentFlags)}
    `;
    paintWarning();
    attachMaster();
    attachCards();
  };

  const paintCard = (btn, flag, isActive) => {
    btn.classList.toggle("on", isActive);
    btn.classList.toggle("off", !isActive);
    btn.querySelector(".vuln-status").textContent = isActive ? "VULNERABLE" : "SEGURO";

    const cat = META[flag].cat;
    const catItems = Object.keys(META).filter((k) => META[k].cat === cat);
    const small = btn.closest(".vuln-category").querySelector("h3 small");
    if (small) {
      const activeCount = catItems.filter((f) => currentFlags[f]).length;
      small.textContent = `(${activeCount}/${catItems.length} activas)`;
    }

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
    content.innerHTML = loader("Cargando estado…");
    try {
      const data = await getVulnerabilities();
      paintAll(data);
    } catch (err) {
      content.innerHTML = emptyState({
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
      const target = !Object.values(currentFlags).every((v) => v === true);
      try {
        const data = await setAllVulnerabilities(target);
        // El master toggle cambia TODOS los flags → si alguno es JWT, avisar.
        const anyJwtFlagChanged = Object.keys(META).some(
          (f) => JWT_TOKEN_REFRESH_FLAGS.has(f)
        );
        if (anyJwtFlagChanged) {
          for (const f of JWT_TOKEN_REFRESH_FLAGS) jwtFlagsChanged.add(f);
        }
        paintAll(data);
        flash(target ? "⚠️ TODAS las vulnerabilidades ACTIVADAS" : "🔒 TODAS las vulnerabilidades MITIGADAS", target ? "warn" : "success");
      } catch (err) {
        flash(`Error: ${err.message}`, "error");
        btn.disabled = false;
      }
    });
  };

  const attachCards = () => {
    content.querySelectorAll(".vuln-card").forEach((card) => {
      card.addEventListener("click", async (e) => {
        const btn = e.currentTarget;
        const flag = btn.dataset.flag;
        const prev = currentFlags[flag];
        btn.disabled = true;
        try {
          const data = await toggleVulnerability(flag, !prev);
          currentFlags = data.flags;
          if (JWT_TOKEN_REFRESH_FLAGS.has(flag)) {
            jwtFlagsChanged.add(flag);
          }
          paintCard(btn, flag, currentFlags[flag]);
          paintWarning();
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