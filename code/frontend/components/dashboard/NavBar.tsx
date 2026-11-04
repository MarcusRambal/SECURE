"use client";

import Image from "next/image";
import Link from "next/link";
import styles from "./NavBar.module.css";

export type DashboardView = "config" | "panel";

interface NavBarProps {
  active: DashboardView;
  onChange: (view: DashboardView) => void;
}

const TABS: { id: DashboardView; label: string }[] = [
  { id: "config", label: "Configuración" },
  { id: "panel", label: "Panel" },
];

export const NavBar = ({ active, onChange }: NavBarProps) => {
  return (
    <header className={styles.header}>
    <nav className={styles.navBar} aria-label="Navegación del escaneo">
      <Link className={styles.homeLink} href="/" aria-label="SECURE, volver a la página principal">
        <Image className={styles.logo} src="/LOBSTER.svg" alt="" width={42} height={42} />
        <span>SECURE</span>
      </Link>
      <div className={styles.tabs}>
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
      </div>
    </nav>
    </header>
  );
};
