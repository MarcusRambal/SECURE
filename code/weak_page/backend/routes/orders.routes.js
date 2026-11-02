import { Router } from "express";
import { requireAuth } from "../middleware/auth.js";
import * as orders from "../controllers/orders.controller.js";

const router = Router();

router.post("/", requireAuth, orders.createOrder);
router.get("/", requireAuth, orders.listOrders);
router.get("/:id", requireAuth, orders.getOrder);

export default router;