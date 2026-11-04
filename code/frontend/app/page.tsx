import Image from "next/image";
import Link from "next/link";
import ParticleBackground from "@/components/ParticleBackground";
import styles from "./page.module.css";

export default function Home() {
  return (
    <div className={styles.mainWindowContainer}>
      <ParticleBackground />

      <header className={styles.siteHeader}>
        <nav className={styles.navigation} aria-label="Navegación principal">
          <a className={styles.logoContainer} href="#inicio" aria-label="SECURE, ir al inicio">
            <Image className={styles.logoImage} src="/LOBSTER.svg" alt="" width={42} height={42} />
            <span className={styles.logoTitle}>SECURE</span>
          </a>
          <div className={styles.navigationLinks}>
            <a href="#SaberMas">Saber más</a>
            <a href="#Capacidad">Capacidades</a>
            <a className={styles.repositoryLink} href="https://github.com/MarcusRambal/SECURE/tree/main">
              Repositorio
            </a>
            <Link className={styles.navButton} href="/dashboard">Probar</Link>
          </div>
        </nav>
      </header>

      <main className={styles.mainContent}>
        <section id="inicio" className={styles.hero} aria-labelledby="brand-title">
          <div className={styles.heroContent}>
            <div className={styles.heroLogoFrame}>
              <Image className={styles.heroLogo} src="/LOBSTER.svg" alt="" width={150} height={150} priority />
            </div>
            <h1 className={styles.brandTitle} id="brand-title">SECURE</h1>
            <p className={styles.heroSubtitle}>Busca y valida vulnerabilidades web con inteligencia artificial.</p>
            <p className={styles.heroDescription}>
              Inserta el análisis, sigue cada etapa y consulta los hallazgos en un solo lugar.
            </p>
            <div className={styles.heroActions}>
              <Link className={styles.primaryButton} href="/dashboard">Comenzar análisis</Link>
              <a className={styles.secondaryButton} href="#SaberMas">Conocer SECURE</a>
            </div>
            <p className={styles.authorizationNote}>Úsalo únicamente en sistemas que tengas autorización para evaluar.</p>
          </div>
        </section>

        <section id="SaberMas" className={styles.aboutSection} aria-labelledby="about-title">
          <div className={styles.aboutContent}>
            <p className={styles.eyebrow}>Cómo funciona</p>
            <h2 id="about-title">Acerca de <span className={styles.secureWord}>SECURE</span></h2>
            <p>
              SECURE es un sistema multiagente que coordina herramientas para detectar,
              validar y dar seguimiento a vulnerabilidades web.
            </p>
            <h3>Inicia un análisis</h3>
            <p>
              Ingresa la URL objetivo, carga el informe de scraping en formato JSON y
              selecciona la categoría y el tipo de ataque. Para algunas pruebas también
              necesitarás un token de sesión. El panel muestra el progreso, los hallazgos
              y el reporte final.
            </p>
          </div>
          <div className={styles.statsBar} aria-label="Etapas del análisis">
            <div className={styles.statItem}><span className={styles.statNumber}>01</span><span className={styles.statLabel}>Reconocimiento</span></div>
            <div className={styles.statItem}><span className={styles.statNumber}>02</span><span className={styles.statLabel}>Validación</span></div>
            <div className={styles.statItem}><span className={styles.statNumber}>03</span><span className={styles.statLabel}>Reporte final</span></div>
          </div>
        </section>

        <section id="Capacidad" className={styles.detailsSection} aria-labelledby="capabilities-title">
          <div className={styles.vulnerabilitiesPanel}>
            <p className={styles.eyebrow}>Áreas de análisis</p>
            <h2 id="capabilities-title">Capacidades</h2>
            <p className={styles.sectionDescription}>Selecciona el tipo de prueba que necesitas desde el panel de configuración.</p>
            <div className={styles.vulnerabilitiesGrid}>
              <article className={styles.vulnCard}>
                <h3>Inyección</h3>
                <p>Integra herramientas como sqlmap y Dalfox para detectar inyección SQL y XSS.</p>
              </article>
              <article className={styles.vulnCard}>
                <h3>Fallos criptográficos</h3>
                <p>Analiza posibles problemas relacionados con el uso de criptografía y tokens.</p>
              </article>
              <article className={styles.vulnCard}>
                <h3>Control de acceso</h3>
                <p>Evalúa posibles problemas de acceso a recursos. La opción general está marcada como próximamente en el panel.</p>
              </article>
              <article className={styles.vulnCard}>
                <h3>Autenticación</h3>
                <p>Analiza tokens JWT. La opción de autenticación general está marcada como próximamente en el panel.</p>
              </article>
            </div>
          </div>
        </section>
      </main>
      <footer className={styles.footer}>
        <p>SECURE · Análisis de seguridad web</p>
        <div className={styles.footerLinks}>
          <a href="https://github.com/MarcusRambal/SECURE">Repositorio en GitHub</a>
          <span>Contacto: próximamente</span>
        </div>
      </footer>
    </div>
  );
}
