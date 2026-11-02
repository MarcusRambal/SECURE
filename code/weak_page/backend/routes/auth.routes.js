import { Router } from "express";
import rateLimit from "express-rate-limit";
import * as auth from "../controllers/auth.controller.js";
import { isVulnerable } from "../config/securityMode.js";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Demasiados intentos de login. Espera 15 minutos." }
});

/** Aplica el rate limit solo si A5 está mitigado. */
const maybeLimit = (flag) => (req, res, next) =>
  isVulnerable(flag, req) ? next() : loginLimiter(req, res, next);

const router = Router();

router.post("/login", maybeLimit("WEAK_PASSWORD_NO_RATELIMIT"), auth.login);
router.post("/register", auth.register);
router.post("/logout", auth.logout);
router.post("/forgot", auth.forgotPassword);
router.post("/reset-password", auth.resetPassword);

export default router;