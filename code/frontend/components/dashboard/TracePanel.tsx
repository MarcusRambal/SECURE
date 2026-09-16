import { AgentWebSocketEvent } from "../../types/scan";

interface TracePanelProps {
    events: AgentWebSocketEvent[];
}

export const TracePanel = ({ events }: TracePanelProps) => {

    return (
        <section>
            <h2>Traza de agentes</h2>
            {events.length === 0 ? <p>Aguardando eventos del orquestador...</p> : (
                <ol>
                    {events.map((event, index) => (
                        <li key={`${event.timestamp}-${index}`}>
                            <strong>{event.agentName}</strong>
                            <span>{event.payload.message}</span>
                        </li>
                    ))}
                </ol>
            )}
        </section>

    )
}