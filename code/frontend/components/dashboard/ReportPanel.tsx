import { AgentWebSocketEvent } from "../../types/scan";

interface ReportPanelProps {
    vulnerabilities: NonNullable<AgentWebSocketEvent["payload"]["vulnerability"]>[];
    finalReport?: string;
}

export const ReportPanel = ({ vulnerabilities, finalReport }: ReportPanelProps) => {

    return (
        <section>
            <h2>Vulnerabilidades</h2>
            {vulnerabilities.length === 0 ? <p>Aún no se han reportado vulnerabilidades.</p> : (
                <ul>
                    {vulnerabilities.map((vulnerability, index) => (
                        <li key={`${vulnerability.title}-${index}`}>
                            <strong>{vulnerability.title}</strong>
                            <span>{vulnerability.severity} · CVSS {vulnerability.cvssScore}</span>
                        </li>
                    ))}
                </ul>
            )}
            {finalReport && (
                <div>
                    <h3>Informe final</h3>
                    <p>{finalReport}</p>
                </div>
            )}
        </section>

    )

}