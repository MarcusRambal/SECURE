"use client";

import { useState } from "react";
import { useAgentSocket } from "@/hooks/userAgentSockets";
import type { AgentWebSocketEvent } from "@/types/scan";
import { ConfigPanel } from "@/components/dashboard/ConfigPanel";
import { PanelView } from "@/components/dashboard/PanelView";
import { NavBar, type DashboardView } from "@/components/dashboard/NavBar";
import styles from "./page.module.css";

export default function Dashboard() {
    const [view, setView] = useState<DashboardView>("config");
    const [taskId, setTaskId] = useState<string | null>(null);
    const { events, isConnected, isFinished, isFailed, finalReport } = useAgentSocket(taskId);

    const vulnerabilities = events
        .filter((event) => event.eventType === "VULN_DETECTED")
        .map((event) => event.payload.vulnerability)
        .filter((vulnerability): vulnerability is NonNullable<AgentWebSocketEvent["payload"]["vulnerability"]> => Boolean(vulnerability));

    const handleTaskCreated = (id: string) => {
        setTaskId(id);
        setView("panel");
    };

    return (
        <div className={styles.dashboardContainer}>
            <NavBar active={view} onChange={setView} />

            {view === "config" ? (
                <section className={styles.configSection}>
                    <ConfigPanel onTaskCreated={handleTaskCreated} />
                </section>
            ) : (
                <section className={styles.panelSection}>
                    <PanelView
                        taskId={taskId}
                        events={events}
                        vulnerabilities={vulnerabilities}
                        finalReport={finalReport}
                        isConnected={isConnected}
                        isFinished={isFinished}
                        isFailed={isFailed}
                    />
                </section>
            )}
        </div>
    );
}
