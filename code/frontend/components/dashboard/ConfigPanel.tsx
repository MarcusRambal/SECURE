// components/dashboard/ConfigPanel.tsx
"use client";

import { useState, useTransition, type FormEvent } from "react";
import styles from "./ConfigPanel.module.css";

import { submitScanConfigAction } from "../../actions/scanActions";
import { ATTACK_CATEGORIES } from "../configVariables/variables";

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

  const currentAttacks =
    ATTACK_CATEGORIES[selectedCategory as keyof typeof ATTACK_CATEGORIES]
      ?.attacks || [];

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setTokenError(null);

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
          <button
            type="button"
            onClick={handlePasteToken}
            className={styles.pasteButton}
            disabled={!canPasteToken}
          >
            Pegar desde Portapapeles
          </button>
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