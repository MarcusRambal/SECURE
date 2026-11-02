-- Dump de dulceNube.sqlite
-- Generado automáticamente, no compartir

CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, role TEXT);
INSERT INTO users VALUES
  (1, 'Admin Dulce Nube', 'admin@dulcenube.com', '0192023a7bbd73250516f069df18b500', 'admin'),
  (2, 'María López', 'maria@example.com', 'f8461b554d59b3014e8ff5165dc62fac', 'customer'),
  (3, 'Pedro Ruiz', 'pedro@example.com', 'e10adc3949ba59abbe56e057f20f883e', 'customer'),
  (4, 'Lucía Fernández', 'lucia@example.com', '5f4dcc3b5aa765d61d8327deb882cf99', 'customer'),
  (5, 'Carlos Gómez', 'carlos@example.com', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'customer');

CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL);
-- ... omitido por brevedad
