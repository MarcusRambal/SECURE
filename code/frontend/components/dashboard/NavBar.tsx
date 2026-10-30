"use client";

import styles from "./NavBar.module.css";

export type DashboardView = "config" | "panel" | "inicio";

interface NavBarProps {
  active: DashboardView;
  onChange: (view: DashboardView) => void;
}

const TABS: { id: DashboardView; label: string }[] = [
  { id: "config", label: "Configuración" },
  { id: "panel", label: "Panel" },
  { id: "inicio", label: "Secure"}
];

export const NavBar = ({ active, onChange }: NavBarProps) => {
  return (
    <nav className={styles.navBar} aria-label="Navegación del escaneo">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          className={`${styles.tab} ${active === tab.id ? styles.tabActive : ""}`}
          aria-current={active === tab.id ? "page" : undefined}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  );
};
