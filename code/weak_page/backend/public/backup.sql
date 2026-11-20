-- Dump de dulceNube.sqlite
-- Generado automáticamente, no compartir

CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, login_delay_ms INTEGER, role TEXT);
INSERT INTO users VALUES
  (1, 'Admin Dulce Nube', 'admin@dulcenube.com', 'admin123', 0, 'admin'),
  (2, 'María López', 'maria@example.com', 'f8461b554d59b3014e8ff5165dc62fac', 0, 'customer'),
  (3, 'Pedro Ruiz', 'pedro@example.com', '$2b$04$Vm6GM5evGdBTybyiz7QpBe2ygIbO0fNzNoYO/E39T3hXjqbSlZVC6', 0, 'customer'),
  (4, 'Lucía Fernández', 'lucia@example.com', '$2b$12$/H96FpMHCm/diSRbCsgp9OA6AtqfjiOR82WlnTrlEzNVq/qWetzAK', 0, 'customer'),
  (5, 'Carlos Gómez', 'carlos@example.com', '$2b$12$ZN4j5uGjQLYKEj9kry.hPuyw3Gw1slxR5DInuMacAeDc8yhxPoFSO', 1000, 'customer');

CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL);
-- ... omitido por brevedad
