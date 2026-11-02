import express from "express";
import cors from "cors";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { vulnerabilityOverride } from "../middleware/vulnerabilityOverride.js";
import { requestLogger }         from "../middleware/requestLogger.js";
import { syntheticCrawlerGuard } from "../middleware/syntheticCrawlerGuard.js";
import { errorHandler, notFoundHandler } from "../middleware/errorHandler.js";
import { isVulnerable, resolvedFlags, currentGlobalMode } from "../config/securityMode.js";

import authRoutes from "../routes/auth.routes.js";
import { requireAuth } from "../middleware/auth.js";
import * as authController from "../controllers/auth.controller.js";
import productsRoutes from "../routes/products.routes.js";
import contactRoutes from "../routes/contact.routes.js";
// ── imports nuevos ──────────────────────────────
import ordersRoutes from "../routes/orders.routes.js";
import adminRoutes  from "../routes/admin.routes.js";
import { getCryptoDebugInfo } from "../utils/crypto.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = path.join(ROOT, "public");

const staticOpen   = express.static(PUBLIC_DIR, { dotfiles: "allow" });
const staticClosed = express.static(PUBLIC_DIR, { dotfiles: "deny"  });

const BLOCKED = [
  /\.env$/i, /\.sql$/i, /\.log$/i, /\.sqlite3?$/i, /\.bak$/i,
  /^\/logs\//i, /^\/admin\//i, /^\/backup/i, /^\/database\.sqlite$/i
];

export function createApp() {
  const app = express();

  app.use(cors({ origin: "*" }));
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true }));

  app.use("/api", syntheticCrawlerGuard);
  app.use(vulnerabilityOverride);
  app.use(requestLogger);

  // Health / estado del lab
  app.get("/api/health", (req, res) => {
    res.json({
      status: "ok",
      securityMode: currentGlobalMode(),
      vulnerabilities: resolvedFlags(req),
      crypto: getCryptoDebugInfo(req)
    });
  });

  // Public con comportamiento dependiente de B3
  app.use((req, res, next) => {
    if (isVulnerable("EXPOSED_SENSITIVE_FILES", req)) return staticOpen(req, res, next);
    if (BLOCKED.some((re) => re.test(req.path))) {
      return res.status(403).json({ message: "Forbidden" });
    }
    staticClosed(req, res, next);
  });

  // Rutas de la API
  app.use("/api/auth", authRoutes);
  app.get("/api/me", requireAuth, authController.me);
  app.use("/api/products", productsRoutes);
  app.use("/api/contact",  contactRoutes);  
  app.use("/api/orders",   ordersRoutes);   
  app.use("/api/admin",    adminRoutes); 

  // 404 y errores
  app.use("/api", notFoundHandler);
  app.use(errorHandler);

  return app;
}