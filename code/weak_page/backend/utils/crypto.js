import crypto from "node:crypto";
import { isVulnerable } from "../config/securityMode.js";

// ❌ C5: clave hardcodeada en el código fuente
// Cualquiera que vea este fichero (via B3, error stack, Git leak...)
// puede descifrar TODOS los datos cifrados con ella.
const HARDCODED_MASTER_KEY = "dulce-nube-master-key-2024-DO-NOT-USE-IN-PROD";

function deriveKey(masterKey) {
  return crypto.scryptSync(masterKey, "dulcenube-salt", 32);
}

export function getMasterKey(req) {
  if (isVulnerable("HARDCODED_CRYPTO_SECRET", req)) {
    return HARDCODED_MASTER_KEY;   // ❌ misma clave en todos los despliegues
  }
  return process.env.AES_KEY;      // ✅ secreto real del entorno
}

/**
 * Cifra los datos del cliente.
 *   C4 activo   → base64 disfrazado de cifrado
 *   C4 mitigado → AES-256-GCM real
 */
export function encryptCustomer(customer, req) {
  if (isVulnerable("BASE64_FAKE_ENCRYPTION", req)) {
    return Buffer.from(JSON.stringify(customer)).toString("base64");
  }
  const key = deriveKey(getMasterKey(req));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(customer), "utf8"), cipher.final()]);
  return `aes:${iv.toString("hex")}:${cipher.getAuthTag().toString("hex")}:${enc.toString("hex")}`;
}

export function decryptCustomer(payload, req) {
  if (!payload) return null;

  if (payload.startsWith("aes:")) {
    const [, ivHex, tagHex, dataHex] = payload.split(":");
    const key = deriveKey(getMasterKey(req));
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
    decipher.setAuthTag(Buffer.from(tagHex, "hex"));
    const dec = Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]);
    return JSON.parse(dec.toString("utf8"));
  }

  // base64
  try {
    return JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

/**
 * C5: cuando el flag está activo, se expone la clave en /api/health.
 * Es un fallo de "information disclosure" + "hardcoded secret".
 */
export function getCryptoDebugInfo(req) {
  if (!isVulnerable("HARDCODED_CRYPTO_SECRET", req)) return null;
  return {
    algorithm: isVulnerable("BASE64_FAKE_ENCRYPTION", req) ? "base64" : "aes-256-gcm",
    keySource: "hardcoded",
    key: HARDCODED_MASTER_KEY
  };
}