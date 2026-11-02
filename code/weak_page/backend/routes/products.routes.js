import { Router } from "express";
import * as products from "../controllers/products.controller.js";

const router = Router();

router.get("/", products.listProducts);
router.get("/categories", products.listCategories);
router.get("/:id/related", products.getRelatedProducts);
router.get("/:id", products.getProduct);

export default router;