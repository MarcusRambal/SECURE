
"use client";

import { useState } from "react";
import styles from "./page.module.css"
import { ConfigPanel } from "../../components/dashboard/ConfigPanel";
import { ReportPanel } from "../../components/dashboard/ReportPanel";
import { TracePanel } from "../../components/dashboard/TracePanel";
import { useAgentSocket } from "../../hooks/userAgentSockets";
import { AgentWebSocketEvent } from "../../types/scan";

export default function ConfigurationWindow() {
    const [taskId, setTaskId] = useState<string | null>(null);
    const { events, isConnected, isFinished, isFailed, finalReport } = useAgentSocket(taskId);
    const vulnerabilities = events
        .filter((event) => event.eventType === "VULN_DETECTED")
        .map((event) => event.payload.vulnerability)
        .filter((vulnerability): vulnerability is NonNullable<AgentWebSocketEvent["payload"]["vulnerability"]> => Boolean(vulnerability));

    return (
        <div className= {styles.configurationWindowContainer}>
            {!taskId ? (
                <ConfigPanel onTaskCreated={setTaskId}/>
            ) : (
                <main className={styles.resultsView}>
                    <header className={styles.resultsHeader}>
                        <div>
                            <p className={styles.eyebrow}>Escaneo en curso</p>
                            <h1>Resultados de la tarea</h1>
                            <code>{taskId}</code>
                        </div>
                        <span className={isFinished ? (isFailed ? styles.statusError : styles.statusComplete) : styles.statusPending}>
                            {isFailed ? "Error" : isFinished ? "Completado" : isConnected ? "Conectado" : "Esperando agentes"}
                        </span>
                    </header>
                    <div className={styles.resultsGrid}>
                        <TracePanel events={events}/>
                        <ReportPanel vulnerabilities={vulnerabilities} finalReport={finalReport}/>
                    </div>
                </main>

            )}
        </div>
    )
}