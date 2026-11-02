💉 INJECTION (5)
#	Reto	Endpoint	Versión vulnerable	Versión segura	Cadena
I1	SQLi Login	POST /auth/login	WHERE email='${email}' AND password='${pw}'	Prepared statement	Bypass auth → admin
I2	SQLi Búsqueda	GET /products?q=	LIKE '%${q}%'	Prepared statement	Filtrado de productos
I3	UNION SQLi (dump de tablas)	GET /products?category=	category='${cat}' → permite UNION SELECT ... FROM users	Prepared statement + whitelist de columnas	Dump de users.password → enlaza con C2
I4	XSS Reflejado	GET /products?q=	Devuelve q en HTML sin escapar	res.json({ q }) o escape en el template	Robo de cookies / token del DOM
I5	XSS Almacenado	POST /contact → GET /contact	Guarda y sirve HTML crudo	Escape al renderizar

Dalfox valida XSS HTTP, pero no ejecuta la SPA ni verifica el flujo de segundo
orden. Recon puede generar para estos casos un plan declarativo de validación
basado en las peticiones y páginas observadas. Validate lo ejecuta mediante la
herramienta genérica `browserXssValidator`, que confirma I4 solo si Chromium
observa ejecución JavaScript en el sink DOM. Para I5, envía un único mensaje con
marca sintética, lo lee en la vista de bandeja y lo elimina al terminar. El
guard del crawler permanece intacto: las escrituras sintéticas generales siguen
recibiendo HTTP 422. El permiso de prueba solo acepta el formato de mensaje, la
lectura del registro marcado y su limpieza, únicamente fuera de
`NODE_ENV=production`.



🔐 CRYPTOGRAPHIC FAILURES (5)
#	Reto	Endpoint	Versión vulnerable	Versión segura	Cadena
C1	Contraseñas en claro	POST /auth/register	INSERT ... password='${pw}'	bcrypt.hash(pw, 12)	Se ve con I3
C2	MD5 legacy en usuarios seed	Login de usuarios antiguos	md5(pw) en la BD	bcrypt	Crackear con rainbow tables / hashcat
C3	Reset token predecible	POST /auth/forgot	token = md5(email), sin TTL	Token aleatorio + TTL + un solo uso	Tomar cuenta de cualquier usuario
C4	Base64 disfrazado de cifrado	GET /orders/:id (PII)	Buffer.from(pii).toString("base64")	AES-GCM con clave del .env	Decodificar PII de otros pedidos (con I3/IDOR)
C5	Secreto hardcodeado	Cualquiera	const KEY = "supersecret123" en auth.controller.js	process.env.JWT_SECRET



🚪 BROKEN ACCESS CONTROL (5)
#	Reto	Endpoint	Versión vulnerable	Versión segura	Cadena
B1	IDOR en pedidos	GET /orders/:id	Devuelve cualquier pedido	WHERE id=? AND user_id=?	Ver pedidos ajenos
B2	Auth ausente en /me y /orders	GET /me, GET /orders	Sin requireAuth	Middleware obligatorio	Enumerar todo
B3	Archivos sensibles expuestos	GET /.env, /backup.sql, /logs/app.log, /admin/notes.txt, /database.sqlite	Servidos como estáticos	Fuera de public/ + bloqueo por extensión	Encontrar JWT_SECRET (enlaza con A2)
B4	Falta de rol en admin	GET /admin/users, POST /admin/vulnerabilities	Cualquier autenticado	requireRole('admin')	Ver todos los usuarios / togglear retos
B5	Mass assignment en registro	POST /auth/register	Acepta role:"admin"	Whitelist de campos


🔑 AUTHENTICATION FAILURES (5)
#	Reto	Endpoint	Versión vulnerable	Versión segura	Cadena
A1	JWT alg:none	Cualquiera con auth	Acepta tokens sin firma	Rechaza alg !== 'HS256'	Convertirse en admin
A2	JWT secreto débil	Cualquiera	jwt.sign(payload, "secret")	Secreto 256 bits del .env	Forjar token con PyJWT
A3	JWT sin expiración	Cualquiera	jwt.sign(payload, secret, {})	expiresIn: "1h"	Token eterno robado
A4	Enumeración de usuarios	POST /auth/login	"Usuario no existe" vs "Contraseña incorrecta"	"Credenciales inválidas"	Descubrir emails válidos
A5	Política débil + sin rate limit	POST /auth/login	Acepta 1234, sin límite	zod + express-rate-limit	Fuerza bruta con hydra/ffuf
## Conectar frontend y backend

El frontend usa el backend por defecto (`API_MODE: "api"`) en `http://localhost:3009/api`. Inicia el backend en una terminal con `npm --prefix backend start` y el servidor estático del frontend en otra con `npm start` (puerto 3008). Si la base de datos aún no existe, inicialízala una vez con `npm --prefix backend run seed`.

Para volver temporalmente a datos locales de demostración, cambia `API_MODE` a `"mock"` en `js/config.js`. Los servicios conservan las mismas interfaces; la URL del backend se configura en `API_BASE_URL`.

## Crawling desde el laboratorio

Con Docker Compose levantado, solicita la herramienta MCP `weakPageCrawler` para recorrer las rutas SPA, completar los formularios visibles con datos sintéticos y registrar cada petición y respuesta con el formato de `deep_crawler`. Ejecuta también interacciones inocuas con los controles de búsqueda y filtros. Las peticiones de escritura incluyen una marca de prueba que el backend rechaza con HTTP 422 antes de ejecutar controladores o persistir datos; el login envía credenciales inválidas de prueba y debe responder 401. El crawler permanece limitado al mismo origen, redacta credenciales y datos personales y no guarda cuerpos mayores a 64 KiB. Solo admite `http://weak-page:3009` en `sec-net`. El informe JSON se guarda en `skills_controller/tools/weak_page_crawler/outputs/`.
