// components/dashboard/ConfigPanel.tsx
"use client";

import {
  useState,
  useTransition,
  type ChangeEvent,
  type FormEvent,
} from "react";
import styles from "./ConfigPanel.module.css";

import { submitScanConfigAction } from "../../actions/scanActions";
import { ATTACK_CATEGORIES } from "../configVariables/variables";
import type { ScrapingReport } from "@/types/scan";

interface ConfigPanelProps {
  onTaskCreated: (taskId: string) => void;
}

export const ConfigPanel = ({ onTaskCreated }: ConfigPanelProps) => {
  const [targetUrl, setTargetUrl] = useState<string>("");
  const [selectedCategory, setSelectedCategory] = useState<string>("injection");
  const [selectedAttack, setSelectedAttack] = useState<string>(
    ATTACK_CATEGORIES.injection.attacks[0].id
  );
  const [sessionToken, setSessionToken] = useState<string>("");
  const [scrapingReport, setScrapingReport] = useState<ScrapingReport | null>(
    null
  );
  const [scrapingFileName, setScrapingFileName] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const isAuthFailure = selectedCategory === "auth_failure";
  const needsToken = selectedAttack === "jwt" || isAuthFailure;
  const isCryptoInspector = selectedAttack === "crypto_inspector";
  const canPasteToken = needsToken || isCryptoInspector;

  const handleCategoryChange = (key: string) => {
    setSelectedCategory(key);
    const firstAttackOfNewCategory =
      ATTACK_CATEGORIES[key as keyof typeof ATTACK_CATEGORIES].attacks[0].id;
    setSelectedAttack(firstAttackOfNewCategory);
  };

  const handlePasteToken = async () => {
    setTokenError(null);
    try {
      const clip = await navigator.clipboard.readText();
      if (!clip || !clip.trim()) {
        setTokenError("El portapapeles está vacío.");
        return;
      }

      let clean = clip.trim().replace(/^["']|["']$/g, "");
      if (clean.toLowerCase().startsWith("bearer ")) {
        clean = clean.slice(7).trim();
      }

      if (clean.split(".").length !== 3) {
        setTokenError(
          "El JWT no tiene el formato esperado (header.payload.signature)."
        );
        return;
      }

      setSessionToken(clean);
    } catch (err) {
      console.error("[clipboard]", err);
      setTokenError(
        "No se pudo leer el portapapeles (revisa los permisos del navegador)."
      );
    }
  };

  const handleScrapingFileChange = async (
    event: ChangeEvent<HTMLInputElement>
  ) => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    setError(null);
    setScrapingReport(null);
    setScrapingFileName("");

    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".json")) {
      setError("Selecciona un archivo con extensión .json.");
      input.value = "";
      return;
    }

    try {
      const parsed: unknown = JSON.parse(await file.text());
      if (!isScrapingReport(parsed)) {
        setError(
          "El JSON debe incluir target, observed_endpoints y requests con el formato esperado."
        );
        input.value = "";
        return;
      }

      setScrapingReport(parsed);
      setScrapingFileName(file.name);
    } catch {
      setError("No se pudo leer el JSON. Comprueba que el archivo sea válido.");
      input.value = "";
    }
  };

  const currentAttacks =
    ATTACK_CATEGORIES[selectedCategory as keyof typeof ATTACK_CATEGORIES]
      ?.attacks || [];

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setTokenError(null);

    if (!scrapingReport) {
      setError("Selecciona un informe JSON de scraping antes de continuar.");
      return;
    }

    if (needsToken) {
      if (!sessionToken.trim()) {
        setTokenError("Este ataque requiere un token de sesión válido.");
        return;
      }
    }

    if ((needsToken || isCryptoInspector) && sessionToken.trim()) {
      if (sessionToken.trim().split(".").length !== 3) {
        setTokenError(
          "El token no tiene el formato esperado (header.payload.signature)."
        );
        return;
      }
    }

    const payload = {
      targetUrl,
      category: selectedCategory,
      attackType: selectedAttack,
      scrapingReport,
      ...(canPasteToken && sessionToken.trim()
        ? { sessionToken: sessionToken.trim() }
        : {}),
    };

    startTransition(async () => {
      const response = await submitScanConfigAction(payload);

      if (!response.success) {
        setError(response.error ?? "No se pudo crear la tarea.");
        return;
      }

      if (!response.data) {
        setError("La API no devolvió un identificador de tarea.");
        return;
      }

      onTaskCreated(response.data.taskId);
    });
  };

  return (
    <form className={styles.formContent} onSubmit={handleSubmit}>
      <span className={styles.sectionLabel}>Url</span>
      <div className={styles.fieldGroup}>
        <input
          id="targetUrl"
          type="url"
          placeholder="Ingrese URL"
          aria-label="Target URL"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className={styles.inputUrl}
          required
        />
      </div>

      <div className={styles.fieldGroup}>
        <label htmlFor="scrapingReport" className={styles.label}>
          Informe de scraping (.json)
        </label>
        <input
          id="scrapingReport"
          type="file"
          accept=".json,application/json"
          aria-label="Informe JSON de scraping"
          onChange={handleScrapingFileChange}
          className={styles.fileInput}
          disabled={isPending}
          required
        />
        {scrapingFileName && (
          <p className={styles.fileHint}>Archivo cargado: {scrapingFileName}</p>
        )}
      </div>

      <hr className={styles.divider} />

      {/* Categorías de ataque */}
      <div className={styles.fieldGroup}>
        <span className={styles.sectionLabel}>Categorías</span>
        <div className={styles.radioButtons}>
          {Object.entries(ATTACK_CATEGORIES).map(([key, category]) => (
            <label key={key}>
              <input
                type="radio"
                name="attackCategory"
                value={key}
                checked={selectedCategory === key}
                onChange={() => handleCategoryChange(key)}
              />
              <span>{category.label}</span>
            </label>
          ))}
        </div>
      </div>

      <hr className={styles.divider} />

      {/* Ataques específicos */}
      <div className={styles.fieldGroup}>
        <span className={styles.sectionLabel}>Ataques</span>
        <div className={styles.radioButtons}>
          {currentAttacks.map((attack) => (
            <label key={attack.id}>
              <input
                type="radio"
                name="specificAttack"
                value={attack.id}
                checked={selectedAttack === attack.id}
                onChange={(e) => setSelectedAttack(e.target.value)}
              />
              <span>{attack.label}</span>
            </label>
          ))}
        </div>
      </div>

      <hr className={styles.divider} />

      {/* Campo de Token */}
      <div className={styles.fieldGroup}>
        <div className={styles.tokenHeader}>
          <label htmlFor="sessionToken" className={styles.label}>
            Token JWT / Sesión {needsToken ? "(Requerido)" : "(Opcional)"}
          </label>
        </div>
        <input
          id="sessionToken"
          type="text"
          placeholder={
            isCryptoInspector
              ? "Opcional: pegue un token JWT para analizar"
              : "Ingrese Token de sesión"
          }
          value={sessionToken}
          onChange={(e) => setSessionToken(e.target.value)}
          className={`${styles.inputUrl} ${
            !canPasteToken ? styles.inputDisabled : ""
          }`}
          disabled={!canPasteToken}
        />
        {tokenError && <p className={styles.error}>{tokenError}</p>}
      </div>

      <div className={styles.submitContainer}>
        <button
          type="submit"
          className={styles.submitButton}
          disabled={isPending}
        >
          {isPending ? "Encolando..." : "Iniciar Escaneo"}
        </button>
      </div>

      {error && (
        <p role="alert" className={styles.error}>
          {error}
        </p>
      )}
    </form>
  );
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isScrapingReport(value: unknown): value is ScrapingReport {
  if (
    !isRecord(value) ||
    typeof value.target !== "string" ||
    !value.target.trim() ||
    !Array.isArray(value.observed_endpoints) ||
    !Array.isArray(value.requests)
  ) {
    return false;
  }

  const validEndpoints = value.observed_endpoints.every(
    (endpoint) =>
      isRecord(endpoint) &&
      typeof endpoint.method === "string" &&
      typeof endpoint.path === "string" &&
      isStringArray(endpoint.query_parameters)
  );
  const validRequests = value.requests.every((request) => {
    if (
      !isRecord(request) ||
      typeof request.id !== "string" ||
      typeof request.method !== "string" ||
      typeof request.url !== "string" ||
      typeof request.path !== "string" ||
      typeof request.request_line !== "string" ||
      typeof request.resource_type !== "string" ||
      !isStringArray(request.query_parameters) ||
      !isRecord(request.query_values) ||
      !isRecord(request.request_headers) ||
      (request.request_body !== null && !isRecord(request.request_body)) ||
      !isStringArray(request.observed_on) ||
      !isRecord(request.response)
    ) {
      return false;
    }

    const response = request.response;
    const responseBody = response.body;
    return (
      (typeof response.status === "number" || response.status === null) &&
      typeof response.status_text === "string" &&
      isRecord(response.headers) &&
      isRecord(responseBody) &&
      typeof responseBody.captured === "boolean" &&
      typeof responseBody.content_type === "string" &&
      "data" in responseBody
    );
  });

  return validEndpoints && validRequests;
}
