import { Router } from "express";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { isVulnerable } from "../config/securityMode.js";
import * as admin from "../controllers/admin.controller.js";

// B4: en modo vulnerable cualquier autenticado pasa; en seguro, solo admin.
const adminGate = (req, res, next) => {
  requireAuth(req, res, () => {
    if (isVulnerable("MISSING_ROLE_CHECK_ADMIN", req)) return next();
    requireRole("admin")(req, res, next);
  });
};

const router = Router();

router.get("/users",           adminGate, admin.listAllUsers);
router.get("/vulnerabilities", adminGate, admin.getVulnerabilities);
router.post("/vulnerabilities", adminGate, admin.toggleVulnerabilities);
router.get("/crypto-debug",    adminGate, admin.cryptoDebug);

export default router;