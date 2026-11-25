import type { AuditFinding, AuditReportData } from "./AuditReport";
import type { AgentWebSocketEvent } from "../../types/scan";

type ScanFinding = NonNullable<AgentWebSocketEvent["payload"]["vulnerability"]>;

const isCount = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0;

export function buildAuditReport(
  taskId: string,
  targetUrl: string,
  attackType: string,
  events: AgentWebSocketEvent[],
): AuditReportData {
  const findings = events
    .filter((event) => event.eventType === "VULN_DETECTED")
    .map((event) => event.payload.vulnerability)
    .filter((finding): finding is ScanFinding => Boolean(finding));
  const validation = [...events].reverse().find(
    (event) => event.agentName === "validate" && event.eventType === "TOOL_EXECUTION",
  );
  const recon = [...events].reverse().find(
    (event) => event.agentName === "recon" && event.eventType === "TOOL_EXECUTION",
  );
  const completion = [...events].reverse().find((event) => event.eventType === "SCAN_COMPLETE");
  const reportedFindings = validation?.payload.details?.vulnerabilitiesCount;
  const reportedObjectives = recon?.payload.details?.endpointsCount;
  const totalFindings = isCount(reportedFindings) ? reportedFindings : findings.length;
  const severity: AuditReportData["summary"]["severity"] = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  };
  const reportFindings: AuditFinding[] = findings.map((finding) => {
    severity[finding.severity] = (severity[finding.severity] ?? 0) + 1;
    const command = finding.pocScript?.trim();
    return {
      id: finding.findingId || undefined,
      title: finding.title,
      severity: finding.severity,
      type: finding.title,
      cwe: finding.cwe || undefined,
      tool: finding.toolsUsed?.join(", ") || undefined,
      endpoint: finding.endpoint || undefined,
      evidence: finding.evidence || undefined,
      command: command && !/^comando no verificado/i.test(command) ? command : undefined,
    };
  });
  const hasCompleteActiveData =
    attackType === "bac_default" &&
    isCount(reportedFindings) &&
    (validation?.payload.details?.status === "SUCCESS" || validation?.payload.details?.status === "PARTIAL") &&
    findings.length === totalFindings &&
    findings.every((finding) => Boolean(finding.attackDemonstrated));

  return {
    taskId,
    target: targetUrl,
    modalidad: attackType,
    date: completion?.timestamp,
    partial: completion?.payload.details?.status === "PARTIAL" ||
      validation?.payload.details?.status === "PARTIAL",
    summary: {
      totalObjectives: isCount(reportedObjectives) ? reportedObjectives : null,
      objectivesLabel: "Objetivos priorizados",
      totalFindings,
      severity,
      activeConfirmations: hasCompleteActiveData
        ? findings.filter((finding) => finding.attackDemonstrated === "active_access_control_exploitation").length
        : null,
    },
    findings: reportFindings,
  };
}
