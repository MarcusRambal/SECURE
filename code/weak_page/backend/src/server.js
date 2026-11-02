import "dotenv/config";
import { createApp } from "./app.js";
import { VULNERABILITIES } from "../config/vulnerabilities.js";
import { DB_FILE_PATH } from "../utils/sql.js";
import fs from "node:fs";

const PORT = Number(process.env.PORT || 3009);
const MODE = process.env.SECURITY_MODE || "vulnerable";

if (!fs.existsSync(DB_FILE_PATH)) {
  console.error("✖ No existe la base de datos. Ejecuta primero:  npm run seed");
  process.exit(1);
}

const app = createApp();

app.listen(PORT, () => {
  console.log("");
  console.log("  ⚠️  LAB VULNERABLE — Dulce Nube backend");
  console.log("  ────────────────────────────────────────");
  console.log(`  Modo global     : ${MODE.toUpperCase()}`);
  console.log(`  Puerto          : ${PORT}`);
  console.log(`  Health check    : http://localhost:${PORT}/api/health`);
  console.log(`  DB              : ${DB_FILE_PATH}`);
  console.log("  ────────────────────────────────────────");

  if (MODE !== "secure") {
    const activas = Object.entries(VULNERABILITIES).filter(([, v]) => v).length;
    console.log(`  Flags vulnerables activos: ${activas}/${Object.keys(VULNERABILITIES).length}`);
    console.log("  Solo uso local. NO desplegar en producción.");
  }
  console.log("");
});