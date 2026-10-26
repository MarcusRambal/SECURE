// components/dashboard/ConfigPanel.tsx
"use client";

import { useState, useTransition } from "react";
import styles from "./ConfigPanel.module.css";

import { submitScanConfigAction } from '../../actions/scanActions'

import { ATTACK_CATEGORIES, AVAILABLE_LLM_MODELS } from "../configVariables/variables";

interface ConfigPanelProps {
  onTaskCreated: (taskId: string) => void;
}

export const ConfigPanel = ({ onTaskCreated }: ConfigPanelProps) => {
  const [activeTab, setActiveTab] = useState<"basic" | "advanced">("basic");
  const [targetUrl, setTargetUrl] = useState<string>("");
  const [selectedCategory, setSelectedCategory] = useState<string>("injection");
  const [selectedAttack, setSelectedAttack] = useState<string>(ATTACK_CATEGORIES.injection.attacks[0].id);
  const [agentModels, setAgentModels] = useState({scanner: "Qwen 2.5 7B (Ollama / Local)", attacker: "Qwen 2.5 7B (Ollama / Local)", reporter: "Qwen 2.5 7B (Ollama / Local)"});
  const [token, setToken] = useState<string>("");
  const [tokenPasted, setTokenPasted] = useState<boolean>(false);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  // JWT solo se muestra cuando el ataque seleccionado es jwt.
  const needsToken = selectedAttack === "jwt";

  const handleCategoryChange = (key: string) => {
    setSelectedCategory(key);
    const firstAttackOfNewCategory = ATTACK_CATEGORIES[key as keyof typeof ATTACK_CATEGORIES].attacks[0].id;
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
      // Limpieza defensiva por si el usuario copia con "Bearer " o comillas
      let clean = clip.trim().replace(/^["']|["']$/g, "");
      if (clean.toLowerCase().startsWith("bearer ")) {
        clean = clean.slice(7).trim();
      }
      // Validación mínima: header.payload.signature
      if (clean.split(".").length !== 3) {
        setTokenError("El JWT no tiene el formato esperado (header.payload.signature).");
        return;
      }
      setToken(clean);
      setTokenPasted(true);
    } catch (err) {
      console.error("[clipboard]", err);
      setTokenError("No se pudo leer el portapapeles (revisa los permisos del navegador).");
    }
  };

  const currentAttacks = ATTACK_CATEGORIES[selectedCategory as keyof typeof ATTACK_CATEGORIES]?.attacks || [];

  const handleSubmit = (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    setTokenError(null);

    // Validar token si el ataque lo requiere
    if (needsToken) {
      if (!token.trim()) {
        setTokenError("El ataque JWT requiere un token de sesión válido.");
        return;
      }
      if (token.trim().split(".").length !== 3) {
        setTokenError("El token no tiene el formato esperado (header.payload.signature).");
        return;
      }
    }

    const payload = {
      targetUrl,
      category: selectedCategory,
      attackType: selectedAttack,
      agentModels,
      // Solo se envía si el ataque lo requiere
      ...(needsToken ? { token: token.trim() } : {}),
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
    <>
      <h2 className={styles.configurationTitle}>Choose your configuration</h2>

      <div className={styles.tabHeader}>
        <button type="button" className={`${styles.tabButton} ${activeTab === "basic" ? styles.activeTab : ""}`} onClick={() => setActiveTab("basic")}>
          Configuración Básica
        </button>

        <button type="button" className={`${styles.tabButton} ${activeTab === "advanced" ? styles.activeTab : ""}`} onClick={() => setActiveTab("advanced")}>
          Configuración Avanzada
        </button>
      </div>

      <form className={styles.formContent} onSubmit={handleSubmit}>

        {/* URL de Destino */}
        <div className={styles.fieldGroup}>
          <label htmlFor="targetUrl" className={styles.label}>
            Target URL
          </label>
          <input
            id="targetUrl"
            type="url"
            placeholder="https://ejemplo.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className={styles.inputUrl}
            required
          />
        </div>

        {/* Categorías */}
        <div className={styles.fieldGroup}>
          <label htmlFor="attackCategories" className={styles.label}>
            Attack Categories
          </label>
          <div className={styles.radioButtons}>
            {Object.entries(ATTACK_CATEGORIES).map(([Key, category]) => (
              <label key={Key}>
                <input
                  type="radio"
                  name="attackCategory"
                  value={Key}
                  checked={selectedCategory === Key}
                  onChange={() => handleCategoryChange(Key)}
                />
                <span> {category.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Ataque específico */}
        <div className={styles.fieldGroup}>
          <label htmlFor="specificAttack" className={styles.label}>
            Ataque específico
          </label>
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

        {/* Campo condicional: solo visible para ataques JWT */}
        {needsToken && (
          <div className={styles.tokenFieldGroup}>
            <label htmlFor="jwtToken" className={styles.label}>
              JWT de sesión
            </label>
            <textarea
              id="jwtToken"
              className={styles.tokenInput}
              placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7..."
              value={token}
              onChange={(e) => { setToken(e.target.value); setTokenPasted(false); }}
              spellCheck={false}
              autoComplete="off"
            />
            <p className={styles.tokenHint}>
              Pega aquí un token JWT válido de un usuario de prueba del objetivo.
              Obtenlo tras hacer login (<code>POST /rest/user/login</code> → campo <code>authentication.token</code>)
              o desde las DevTools del navegador (<code>localStorage</code> o <code>Authorization: Bearer</code>).
            </p>
            <div className={styles.tokenActions}>
              <button
                type="button"
                onClick={handlePasteToken}
                className={styles.tokenButton}
              >
                Pegar del portapapeles
              </button>
              {tokenPasted && <span className={styles.tokenStatus}>✓ Token cargado</span>}
            </div>
            {tokenError && <p className={styles.tokenError} role="alert">{tokenError}</p>}
          </div>
        )}

        {/* Configuración Avanzada */}
        {activeTab === "advanced" && (
          <div className={styles.advancedSection}>
            <h3 className={styles.subTitle}>Asignación de Modelos por Agente</h3>

            <div className={styles.fieldGroup}>
              <label className={styles.label}>Agente Reconocimiento & Scan</label>
              <div className={styles.radioButtons}>
                {AVAILABLE_LLM_MODELS.map((model) => (
                  <label key={model} className={styles.radioLabel}>
                    <input
                      type="radio"
                      name="agent-scanner"
                      value={model}
                      checked={agentModels.scanner === model}
                      onChange={(e) => setAgentModels({ ...agentModels, scanner: e.target.value })}
                    />
                    <span>{model}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className={styles.fieldGroup}>
              <label className={styles.label}>Agente Atacante & Verificador</label>
              <div className={styles.radioButtons}>
                {AVAILABLE_LLM_MODELS.map((model) => (
                  <label key={model} className={styles.radioLabel}>
                    <input
                      type="radio"
                      name="agent-attacker"
                      value={model}
                      checked={agentModels.attacker === model}
                      onChange={(e) => setAgentModels({ ...agentModels, attacker: e.target.value })}
                    />
                    <span>{model}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className={styles.fieldGroup}>
              <label className={styles.label}>Agente Generador de Reportes</label>
              <div className={styles.radioButtons}>
                {AVAILABLE_LLM_MODELS.map((model) => (
                  <label key={model} className={styles.radioLabel}>
                    <input
                      type="radio"
                      name="agent-reporter"
                      value={model}
                      checked={agentModels.reporter === model}
                      onChange={(e) => setAgentModels({ ...agentModels, reporter: e.target.value })}
                    />
                    <span>{model}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className={styles.submitContainer}>
          <button type="submit" className={styles.submitButton} disabled={isPending}>
            {isPending ? "Encolando..." : "Iniciar Escaneo"}
          </button>
        </div>

        {error && <p role="alert">{error}</p>}
      </form>
    </>
  );
}