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
  const [agentModels, setAgentModels] = useState({scanner: "GPT-4o-mini (OpenAI)", attacker: "Claude 3.5 Sonnet (Anthropic)", reporter: "GPT-4o-mini (OpenAI)"});
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  const handleCategoryChange = (key: string) => {
    setSelectedCategory(key);
    const firstAttackOfNewCategory = ATTACK_CATEGORIES[key as keyof typeof ATTACK_CATEGORIES].attacks[0].id;
    setSelectedAttack(firstAttackOfNewCategory);
  };

  const currentAttacks = ATTACK_CATEGORIES[selectedCategory as keyof typeof ATTACK_CATEGORIES]?.attacks || [];

  const handleSubmit = (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    /* const payload = {
        targetUrl,
        category: selectedCategory,
        attackType: selectedAttack,
        // Opcional: podrías explícitamente enviar un flag de modo
        configMode: activeTab, 
        agentModels: activeTab === "advanced" ? agentModels : DEFAULT_AGENT_MODELS,
        }; */
    const payload = {
      targetUrl,
      category: selectedCategory,
      attackType: selectedAttack,
      agentModels,
    };

    // Executamos la Server Action usando React Transition
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

      {/* Pestañas de Navegación */}
      <div className={styles.tabHeader}>
        <button type="button" className={`${styles.tabButton} ${activeTab === "basic" ? styles.activeTab : ""}`} onClick={() => setActiveTab("basic")}>
          Configuración Básica
        </button>

        <button type="button" className={`${styles.tabButton} ${activeTab === "advanced" ? styles.activeTab : ""}`} onClick={() => setActiveTab("advanced")}>
          Configuración Avanzada
        </button>
      </div>

      <form className = {styles.formContent} onSubmit={handleSubmit}>      

        {/* Campo 1: URL de Destino (Común para ambas pestañas) */}
        <div className={styles.fieldGroup}>
          <label htmlFor="targetUrl" className={styles.label}>
            Target URL
          </label>
          <input id="targetUrl"  type="url" placeholder="https://ejemplo.com" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} className={styles.inputUrl} required/>
        </div>{/* URL */}


        {/*Campo 2: Categorias de ataque (Comun para ambas pestañas) */}
        <div className={styles.fieldGroup}>
          <label htmlFor="attackCategories" className={styles.label}>
            Attack Categories
          </label>
                <div className={styles.radioButtons}> 
                    {Object.entries(ATTACK_CATEGORIES).map(([Key, category]) => (
                        <label key={Key}>
                            <input type= "radio" name="attackCategory" value={Key} checked = {selectedCategory === Key} onChange={() => handleCategoryChange(Key)} />
                                <span> {category.label}</span>
                        </label>
                    ))}    
               </div>
               
        </div> {/* Radio Categorias*/}

        {/* Campo 3 : Tipo de ataques segun categorias seleccionadas*/}
        
        <div className={styles.fieldGroup}>
               <label htmlFor="specificAttack" className={styles.label}>
                Ataque especifico
               </label>
            <div className={styles.radioButtons}>
               {currentAttacks.map((attack) => (
            <label key={attack.id} >
                <input type="radio" name="specificAttack" value={attack.id} checked={selectedAttack === attack.id} onChange={(e) => setSelectedAttack(e.target.value)}  />
            <span>{attack.label}</span>
        
            </label>
            ))}
            </div>
        </div>

         {/* Sección Extra solo activa en la Pestaña Avanzada */}
        {activeTab === "advanced" && (
          <div className={styles.advancedSection}>
            <h3 className={styles.subTitle}>Asignación de Modelos por Agente</h3>

            {/* Agente Orquestador (No modificable) 
            <div className={styles.fieldGroup}>
              <label className={styles.label}>
                Agente Orquestador <span className={styles.lockBadge}>Fijo</span>
              </label>
              <input
                type="text"
                value="GPT-4o (Modelo Base No Modificable)"
                disabled
                className={styles.disabledInput}
              />
            </div>
                */}
            {/* Agente Reconocimiento & Scan */}
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
                        onChange={(e) => setAgentModels({ ...agentModels, scanner: e.target.value })} />
                        <span>{model}</span>
                    </label>
                    ))}
                </div>
            </div>

            {/* Agente Verificador / Explotación */}
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
                        onChange={(e) => setAgentModels({ ...agentModels, attacker: e.target.value })} />
                        <span>{model}</span>
                    </label>
                    ))}
                </div>
            </div>

            {/* Agente de Reportes */}
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
                        onChange={(e) => setAgentModels({ ...agentModels, reporter: e.target.value })} />
                        <span>{model}</span>
                    </label>
                    ))}
                </div>
            </div>
           
          </div>
        )}

        {/* Botón de Envío del Formulario */}
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