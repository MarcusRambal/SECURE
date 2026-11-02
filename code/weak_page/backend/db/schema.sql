-- Base de datos del lab Dulce Nube
-- ⚠️ Diseño intencionalmente simplificado

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL,
  email        TEXT UNIQUE NOT NULL,
  password     TEXT NOT NULL,           -- C1/C2: texto plano o MD5 en modo vulnerable
  role         TEXT NOT NULL DEFAULT 'customer',
  reset_token  TEXT,
  reset_expires TEXT,
  created_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL,
  category     TEXT NOT NULL,
  price        REAL NOT NULL,
  description  TEXT,
  image        TEXT,
  stock        INTEGER DEFAULT 0,
  featured     INTEGER DEFAULT 0,
  ingredients  TEXT,
  allergens    TEXT
);

CREATE TABLE IF NOT EXISTS orders (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  code           TEXT UNIQUE,
  user_id        INTEGER,
  customer_json  TEXT NOT NULL,         -- C4: "cifrado" con base64 en modo vulnerable
  items_json     TEXT NOT NULL,
  subtotal       REAL NOT NULL,
  shipping       REAL NOT NULL,
  total          REAL NOT NULL,
  payment_method TEXT,
  status         TEXT DEFAULT 'confirmado',
  created_at     TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS contact_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT,
  email      TEXT,
  subject    TEXT,
  message    TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_orders_user      ON orders(user_id);