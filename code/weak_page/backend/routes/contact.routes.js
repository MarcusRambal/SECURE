import { Router } from "express";
import * as contact from "../controllers/contact.controller.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

router.post("/", contact.sendContact);
router.get("/xss-inbox/:id", contact.getValidationProbe);
router.get("/", requireAuth, contact.listContacts);
router.delete("/:id", contact.deleteValidationProbe);

export default router;