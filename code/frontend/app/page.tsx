// app/page.tsx

'use client'

import styles from "./page.module.css";
import ParticleBackground from "@/components/ParticleBackground";
import Image from "next/image";

export default function Home() {
  return (
    <div className={styles.mainWindowContainer}>
      <ParticleBackground />

      <header className={styles.siteHeader}>
          <nav className={styles.navigation} aria-label="Navegación principal">
              <div className={styles.navigationLinks}>
                 <div className={styles.logoContainer}>
                     <img className={styles.lobster} id="lobster" src="/LOBSTER.svg" alt="Langosta" width={50} height={50} />
                     <span className={styles.logoTitle}>Secure</span>
                 </div>
                  <a href="#SaberMas">Saber más</a>
                  <a href="#Capacidad">Capacidad</a>
                  <a id="Probar" href="/dashboard">Probar</a>
              </div>
              <a className={styles.repositoryLink} href="https://github.com/MarcusRambal/SECURE/tree/main" aria-label="Repositorio en GitHub">
                  <span>Repositorio</span>
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path fill="currentColor" d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.1c-3.1.68-3.75-1.32-3.75-1.32-.5-1.29-1.24-1.63-1.24-1.63-1.02-.7.08-.69.08-.69 1.12.08 1.71 1.15 1.71 1.15 1 1.7 2.62 1.21 3.26.93.1-.72.39-1.21.71-1.49-2.48-.28-5.09-1.24-5.09-5.53 0-1.22.44-2.22 1.15-3-.12-.28-.5-1.42.11-2.96 0 0 .94-.3 3.05 1.15a10.6 10.6 0 0 1 5.55 0c2.11-1.45 3.05-1.15 3.05-1.15.61 1.54.23 2.68.11 2.96.72.78 1.15 1.78 1.15 3 0 4.3-2.62 5.25-5.11 5.52.4.35.76 1.03.76 2.08v3.08c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9Z"/>
                  </svg>
              </a>
          </nav>
      </header>

      <main>
          <section className={styles.hero} aria-labelledby="brand-title">
              <div className={styles.heroContent}>
                  <Image className={styles.lobster} id="lobster" src="/LOBSTER.svg" alt="Langosta" width={200} height={200} />
                  <h1 className={styles.brandTitle} id="brand-title">SECURE</h1>
                  <h2>Busca y valida <span>vulnerabilidades web</span> con Inteligencia Artificial</h2>
              </div>
              <a href="#SaberMas" className={styles.scrollIndicator} aria-label="Ver métricas y vulnerabilidades">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="m6 9 6 6 6-6"/>
                  </svg>
              </a>
          </section>

          <section id="SaberMas" className={styles.aboutSection} aria-label="Acerca de SECURE">
                <div className={styles.aboutContent}>
                    <article className={styles.aboutArticle}>
                        <h1>Acerca de Secure</h1>
                        <p>SECURE es un Sistema multiagente orquestado para la detección, validación ética y trazabilidad de vulnerabilidades web a través de una secuencia automatizada de análisis e interpretación de herramientas.</p> 

                        <h1>Uso</h1> 
                        <p>Para utilizar SECURE, simplemente ingrese la URL objetivo y el tipo de ataque, posteriormente el sistema se encargará de detectar y validar vulnerabilidades web de manera automatizada.</p>  

                        <h1></h1>                
                    </article>
                    
                </div>

                <div className={styles.statsBar}>
                  <div className={styles.statItem}>
                      <span className={styles.statNumber}>5</span>
                      <span className={styles.statLabel}>Herramientas de seguridad ofensiva</span>
                  </div>
                  <div className={styles.statItem}>
                      <span className={styles.statNumber}>3</span>
                      <span className={styles.statLabel}>Agentes de inteligencia artificial</span>
                  </div>
                  <div className={styles.statItem}>
                      <span className={styles.statNumber}>4</span>
                      <span className={styles.statLabel}>Categorias de ataque</span>
                  </div>
              </div>
          </section>

          <section id="Capacidad" className={styles.detailsSection} aria-label="Componentes y Métricas">
              

              <div className={styles.vulnerabilitiesPanel}>
                  <h2 className={styles.vulnerabilitiesTitle}>Vulnerabilidades</h2>
                  <div className={styles.vulnerabilitiesGrid}>
                      <article className={`${styles.vulnCard} ${styles.vulnCardInjection}`}>
                          <h3>Injection</h3>
                          <p>Integracion con herramientas de seguridad ofensiva como sqlmap y dalfox para detectar vulnerabilidades de inyección de tipo SQL y XSS</p>
                      </article>
                      <article className={`${styles.vulnCard} ${styles.vulnCardCrypto}`}>
                          <h3>Cryptography failure</h3>
                          <p>Lorem ipsum dolor sit amet consectetur adipiscing elit gravida eu, dis hac lobortis rutrum hendrerit curabitur orci vehicula, mauris sodales aliquet mus ridiculus pellentesque cubilia morbi. Tortor mi rutrum quam maecenas mus montes penatibus praesent, habitant conubia ad sollicitudin taciti sem erat dignissim, posuere orci ridiculus cum fermentum tellus commodo. Montes inceptos blandit netus quis hac hendrerit nibh erat urna, maecenas dictumst morbi litora dignissim eget nulla tortor diam, cras lectus sociosqu feugiat ut nostra mi ornare.</p>
                      </article>
                      <article className={`${styles.vulnCard} ${styles.vulnCardAccess}`}>
                          <h3>Broken Access Control</h3>
                          <p>Lorem ipsum dolor sit amet consectetur adipiscing elit gravida eu, dis hac lobortis rutrum hendrerit curabitur orci vehicula, mauris sodales aliquet mus ridiculus pellentesque cubilia morbi. Tortor mi rutrum quam maecenas mus montes penatibus praesent, habitant conubia ad sollicitudin taciti sem erat dignissim, posuere orci ridiculus cum fermentum tellus commodo. Montes inceptos blandit netus quis hac hendrerit nibh erat urna, maecenas dictumst morbi litora dignissim eget nulla tortor diam, cras lectus sociosqu feugiat ut nostra mi ornare.</p>
                      </article>
                      <article className={`${styles.vulnCard} ${styles.vulnCardAuth}`}>
                          <h3>Broken Authentication</h3>
                          <p>Lorem ipsum dolor sit amet consectetur adipiscing elit gravida eu, dis hac lobortis rutrum hendrerit curabitur orci vehicula, mauris sodales aliquet mus ridiculus pellentesque cubilia morbi. Tortor mi rutrum quam maecenas mus montes penatibus praesent, habitant conubia ad sollicitudin taciti sem erat dignissim, posuere orci ridiculus cum fermentum tellus commodo. Montes inceptos blandit netus quis hac hendrerit nibh erat urna, maecenas dictumst morbi litora dignissim eget nulla tortor diam, cras lectus sociosqu feugiat ut nostra mi ornare.</p>
                      </article>
                  </div>
              </div>
          </section>


      </main>   
        <footer>
            
        </footer>
            
    </div>
  );
}
