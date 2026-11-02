/**
 * Log mínimo de peticiones. En modo vulnerable muestra la ruta completa
 * con query string; en modo seguro oculta los query params.
 */
export function requestLogger(req, res, next) {
  const start = Date.now();
  res.on("finish", () => {
    const ms = Date.now() - start;
    const path = process.env.SECURITY_MODE === "secure"
      ? req.path
      : req.originalUrl;
    console.log(`[${new Date().toISOString()}] ${req.method} ${path} ${res.statusCode} ${ms}ms`);
  });
  next();
}