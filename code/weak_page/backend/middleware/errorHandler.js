/**
 * Gestor central de errores.
 * - Modo vulnerable: devuelve el stack trace completo (aprende a leerlos).
 * - Modo seguro:     mensaje genérico 500.
 */
export function errorHandler(err, req, res, _next) {
  console.error("[ERROR]", err);

  if (process.env.SECURITY_MODE === "secure") {
    return res.status(500).json({ message: "Error interno del servidor" });
  }

  return res.status(500).json({
    message: err.message,
    stack: err.stack,
    sql: err.sql || undefined,
    path: req.originalUrl
  });
}

export function notFoundHandler(req, res) {
  res.status(404).json({
    message: "Recurso no encontrado",
    path: req.originalUrl
  });
}