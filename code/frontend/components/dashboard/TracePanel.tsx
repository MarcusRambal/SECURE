import { AgentWebSocketEvent } from "../../types/scan";

interface TracePanelProps {
    events: AgentWebSocketEvent[];
}

export const TracePanel = ({ events }: TracePanelProps) => {
    const finalEvent = events.find((event) =>
        event.eventType === "SCAN_COMPLETE" || event.eventType === "SCAN_ERROR"
    );
    const timings = finalEvent?.payload.timings;
    const formatDuration = (durationMs: number) =>
        `${new Intl.NumberFormat("es-CO", { maximumFractionDigits: 2 }).format(durationMs / 1000)} s`;

    return (
        <section>
            <h2>Traza de agentes</h2>
            {timings && (
                <div>
                    <h3>Duración del pipeline</h3>
                    <p>Total: {formatDuration(timings.totalMs ?? 0)}</p>
                    <p>Espera inicial en RabbitMQ: {formatDuration(timings.queueWaitMs ?? 0)}</p>
                    {Object.entries(timings.stages ?? {}).map(([stage, timing]) => (
                        <div key={stage}>
                            <strong>{stage}: {formatDuration(timing.durationMs ?? 0)}</strong>
                            <span>
                                {` RabbitMQ publicación: ${formatDuration(timing.publishMs ?? 0)} · `}
                                {`cola: ${formatDuration(timing.queueWaitMs ?? 0)} · `}
                                {`Agente: ${formatDuration(timing.processingMs ?? 0)} · `}
                                {`RPC: ${formatDuration(timing.roundTripMs ?? 0)}`}
                            </span>
                            {timing.tools?.map((tool, index) => (
                                <p key={`${tool.tool}-${index}`}>
                                    {tool.tool}: {`publicación ${formatDuration(tool.publishMs ?? 0)}, `}
                                    {`cola ${formatDuration(tool.queueWaitMs ?? 0)}, `}
                                    {`ejecución ${formatDuration(tool.processingMs ?? 0)}, `}
                                    {`ida y vuelta ${formatDuration(tool.roundTripMs ?? 0)}`}
                                    {tool.status ? ` (${tool.status})` : ""}
                                </p>
                            ))}
                        </div>
                    ))}
                </div>
            )}
            {events.length === 0 ? <p>Aguardando eventos del orquestador...</p> : (
                <ol>
                    {events.map((event, index) => (
                        <li key={`${event.timestamp}-${index}`}>
                            <strong>{event.agentName}</strong>
                            <span>{event.payload.message}</span>
                            {event.durationMs !== undefined && (
                                <span>Duración: {formatDuration(event.durationMs)}</span>
                            )}
                            {event.payload.details && (
                                <pre>{JSON.stringify(event.payload.details, null, 2)}</pre>
                            )}
                        </li>
                    ))}
                </ol>
            )}
        </section>

    )
}