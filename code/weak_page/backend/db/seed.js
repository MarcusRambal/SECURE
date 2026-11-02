// Pobla la base de datos con datos de ejemplo y crea los ficheros del reto B3.
// Uso:  npm run reset   (borra la BD y vuelve a sembrar)

import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const DB_PATH = path.join(ROOT, "db", "dulceNube.sqlite");
const PUBLIC = path.join(ROOT, "public");

const md5 = (s) => crypto.createHash("md5").update(s).digest("hex");

// ─────────────────────────────────────────────────────────────
// Usuarios seed — contraseñas débiles, almacenadas con MD5 (reto C2)
// ─────────────────────────────────────────────────────────────
const USERS = [
  { name: "Admin Dulce Nube", email: "admin@dulcenube.com", password: "admin123", role: "admin"    },
  { name: "María López",      email: "maria@example.com",   password: "maria123", role: "customer" },
  { name: "Pedro Ruiz",       email: "pedro@example.com",   password: "123456",   role: "customer" },
  { name: "Lucía Fernández",  email: "lucia@example.com",   password: "password", role: "customer" },
  { name: "Carlos Gómez",     email: "carlos@example.com",  password: "qwerty",   role: "customer" }
];

// ─────────────────────────────────────────────────────────────
// Productos
// ─────────────────────────────────────────────────────────────
const PRODUCTS = [
  ["Tarta de chocolate",        "Tartas",    25.0, "Bizcocho de cacao con ganache y virutas.",          10, 1, "harina,huevo,chocolate,mantequilla", "gluten,huevo,lácteos"],
  ["Tarta de fresa",            "Tartas",    22.0, "Base de vainilla con fresas frescas y nata.",       8,  1, "harina,huevo,fresa,nata",            "gluten,huevo,lácteos"],
  ["Cheesecake",                "Tartas",    20.0, "Estilo Nueva York con base de galleta.",            12, 0, "queso,galleta,huevo",                "gluten,huevo,lácteos"],
  ["Croissant",                 "Bollería",  2.5,  "Mantequilla francesa, hojaldrado 72h.",             50, 0, "harina,mantequilla,levadura",        "gluten,lácteos"],
  ["Napolitana de chocolate",   "Bollería",  3.0,  "Hojaldre relleno de chocolate negro.",              40, 0, "harina,mantequilla,chocolate",       "gluten,lácteos"],
  ["Ensaimada",                 "Bollería",  2.8,  "Tradicional mallorquina con azúcar glas.",          30, 0, "harina,manteca,azúcar",              "gluten,lácteos"],
  ["Macarons (6u)",             "Galletas",  12.0, "Surtido de frambuesa, pistacho y vainilla.",        20, 1, "almendra,huevo,azúcar",              "frutos secos,huevo"],
  ["Cookies de avena",          "Galletas",  1.5,  "Avena integral y chips de chocolate.",              100,0, "avena,mantequilla,chocolate",        "gluten,lácteos"],
  ["Brownie",                   "Galletas",  2.2,  "Denso, fundente y con nueces.",                     60, 0, "chocolate,mantequilla,huevo,nuez",   "huevo,lácteos,frutos secos"],
  ["Tarta de zanahoria",        "Tartas",    24.0, "Con frosting de queso crema y nueces.",             6,  0, "zanahoria,harina,nuez,queso",        "gluten,huevo,lácteos,frutos secos"],
  ["Eclair de café",            "Bollería",  3.5,  "Masa choux con crema de café.",                     25, 0, "harina,huevo,café,nata",             "gluten,huevo,lácteos"],
  ["Tarta de limón",            "Tartas",    23.0, "Base de sablé y crema de limón.",                   9,  1, "limón,harina,huevo,mantequilla",     "gluten,huevo,lácteos"]
];

// ─────────────────────────────────────────────────────────────
// Pedidos de ejemplo (para el reto IDOR B1 y C4)
// ─────────────────────────────────────────────────────────────
const SAMPLE_CUSTOMERS = [
  { name: "María López",      address: "Calle Mayor 12, 28013 Madrid",      phone: "+34 600 111 222" },
  { name: "Pedro Ruiz",       address: "Av. Diagonal 88, 08019 Barcelona",  phone: "+34 600 333 444" },
  { name: "Lucía Fernández",  address: "Gran Vía 45, 28013 Madrid",         phone: "+34 600 555 666" }
];

// ─────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────
if (fs.existsSync(DB_PATH)) {
  console.log(`[seed] Eliminando BD existente: ${DB_PATH}`);
  fs.rmSync(DB_PATH, { force: true });
  fs.rmSync(`${DB_PATH}-wal`, { force: true });
  fs.rmSync(`${DB_PATH}-shm`, { force: true });
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

console.log("[seed] Aplicando schema.sql");
db.exec(fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8"));

console.log(`[seed] Insertando ${USERS.length} usuarios (MD5 para reto C2)`);
const insertUser = db.prepare(
  "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
);
for (const u of USERS) {
  insertUser.run(u.name, u.email, md5(u.password), u.role);
}

console.log(`[seed] Insertando ${PRODUCTS.length} productos`);
const insertProduct = db.prepare(
  "INSERT INTO products (name, category, price, description, stock, featured, ingredients, allergens, image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
);
for (const [name, cat, price, desc, stock, featured, ing, allerg] of PRODUCTS) {
  insertProduct.run(name, cat, price, desc, stock, featured, ing, allerg, null);
}

console.log("[seed] Insertando pedidos de ejemplo");
const insertOrder = db.prepare(
  "INSERT INTO orders (code, user_id, customer_json, items_json, subtotal, shipping, total, payment_method, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
);
SAMPLE_CUSTOMERS.forEach((cust, i) => {
  const userId = i + 2; // maria=2, pedro=3, lucia=4
  const items = [{ productId: i + 1, name: PRODUCTS[i][0], price: PRODUCTS[i][2], quantity: 2 }];
  const subtotal = items.reduce((s, it) => s + it.price * it.quantity, 0);
  const shipping = subtotal >= 50 ? 0 : 5;
  // En seed guardamos el customer en base64 (consistente con C4 vulnerable)
  const customerJson = Buffer.from(JSON.stringify(cust)).toString("base64");
  insertOrder.run(
    `DN-${1000 + i}`,
    userId,
    customerJson,
    JSON.stringify(items),
    subtotal,
    shipping,
    subtotal + shipping,
    "tarjeta_simulada",
    "confirmado"
  );
});

db.close();
console.log("[seed] Base de datos lista ✔");

// ─────────────────────────────────────────────────────────────
// Reto B3 — Copiar la BD a public/ y crear archivos "sensibles"
// ─────────────────────────────────────────────────────────────
console.log("[seed] Preparando archivos del reto B3 en public/");

fs.mkdirSync(path.join(PUBLIC, "logs"),   { recursive: true });
fs.mkdirSync(path.join(PUBLIC, "admin"),  { recursive: true });

// Copia de la BD (con hash MD5 de admin dentro)
fs.copyFileSync(DB_PATH, path.join(PUBLIC, "database.sqlite"));

// .env falso — coherente con el modo vulnerable (JWT_WEAK_SECRET usa "secret")
fs.writeFileSync(
  path.join(PUBLIC, ".env"),
  [
    "# ⚠️ .env de EJEMPLO — no usar en producción",
    "NODE_ENV=development",
    "PORT=3000",
    "SECURITY_MODE=vulnerable",
    "JWT_SECRET=secret",
    "DB_PATH=./db/dulceNube.sqlite",
    "SMTP_HOST=smtp.dulcenube.lab",
    "SMTP_USER=pasteleria@dulcenube.lab",
    "SMTP_PASS=Lab_Smtp_Password_2024!",
    ""
  ].join("\n")
);

// backup.sql — dump "legacy" con credenciales de admin
fs.writeFileSync(
  path.join(PUBLIC, "backup.sql"),
  [
    "-- Dump de dulceNube.sqlite",
    "-- Generado automáticamente, no compartir",
    "",
    "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, role TEXT);",
    "INSERT INTO users VALUES",
    USERS.map((u, i) =>
      `  (${i + 1}, '${u.name}', '${u.email}', '${md5(u.password)}', '${u.role}')`
    ).join(",\n") + ";",
    "",
    "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL);",
    "-- ... omitido por brevedad",
    ""
  ].join("\n")
);

// app.log — pistas indirectas
fs.writeFileSync(
  path.join(PUBLIC, "logs", "app.log"),
  [
    "[2024-01-15T09:12:04Z] [INFO] Server started on port 3000",
    "[2024-01-15T09:20:11Z] [LOGIN] admin@dulcenube.com / admin123",
    "[2024-01-15T09:22:45Z] [LOGIN] maria@example.com / maria123",
    "[2024-01-15T10:05:32Z] [INFO] Product created: Tarta de limón",
    "[2024-01-15T11:47:12Z] [LOGIN] admin@dulcenube.com / admin123",
    "[2024-01-15T12:01:58Z] [WARN] Deprecated endpoint used: GET /api/v1/users",
    "[2024-01-15T12:15:03Z] [LOGIN] pedro@example.com / 123456",
    ""
  ].join("\n")
);

// admin/notes.txt — notas internas con credenciales
fs.writeFileSync(
  path.join(PUBLIC, "admin", "notes.txt"),
  [
    "NOTAS INTERNAS — NO COMPARTIR",
    "==============================",
    "Credenciales temporales:",
    "  admin@dulcenube.com / admin123",
    "  (cambiar antes del lanzamiento, pendiente desde 2024-01-01)",
    "",
    "TODOs:",
    "  - Quitar ?debug=true del frontend",
    "  - Rotar el JWT_SECRET (actualmente 'secret')",
    "  - Revisar si /backup.sql sigue en el servidor",
    "  - Migrar contraseñas de MD5 a bcrypt",
    "",
    "Contacto sysadmin: sysadmin@dulcenube.lab"
  ].join("\n")
);

// robots.txt — con pistas
fs.writeFileSync(
  path.join(PUBLIC, "robots.txt"),
  [
    "User-agent: *",
    "Disallow: /admin/",
    "Disallow: /logs/",
    "Disallow: /backup.sql",
    "Disallow: /.env",
    "Disallow: /database.sqlite",
    "",
    "Sitemap: /sitemap.xml"
  ].join("\n")
);

console.log("[seed] Archivos del reto B3 creados en public/ ✔");
console.log("[seed] Hecho. Arranca con: npm run dev");