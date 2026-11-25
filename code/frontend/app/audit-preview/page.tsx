import AuditReport, { mockData } from "@/components/dashboard/AuditReport";
import styles from "./page.module.css";

export default function AuditPreview() {
  return (
    <main>
      <p className={styles.notice}>
        Vista de demostración con datos de ejemplo. No está conectada a un escaneo real.
      </p>
      <AuditReport report={mockData} />
    </main>
  );
}
