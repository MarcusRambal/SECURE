# Segundo Informe — Proyecto SECURE

## Resumen / Abstract

El proyecto SECURE propone el diseño e implementación de un sistema multiagente que automatiza la detección y validación de vulnerabilidades web en entornos de laboratorio autorizados. La arquitectura objetivo contempla cuatro agentes especializados (orquestador, reconocimiento, validación y reporte) que colaboran mediante el Model Context Protocol (MCP) y se comunican a través de un broker de mensajes (RabbitMQ), ejecutando herramientas de pentesting reales en contenedores Docker efímeros. El sistema ha sido diseñado para ejecutar nueve skills de ciberseguridad (Katana, SPA Crawler, Deep Crawler, SQLMap, DalFox, Commix, Nuclei, FFuF y JWT Tool) que apuntan a cubrir cuatro categorías del OWASP Top 10: Inyección, Control de Acceso Roto, Fallos de Autenticación y Fallos Criptográficos, con OWASP Juice Shop como entorno autorizado de referencia para las validaciones.

El avance a la fecha incluye la infraestructura de comunicación asíncrona funcionando (RabbitMQ con patrón RPC), el servidor MCP operativo con catálogo dinámico de skills, la ejecución aislada de herramientas en contenedores efímeros, y la migración del backend de modelos de lenguaje desde proveedores en la nube (Groq) hacia un modelo local (Qwen 2.5 servido vía Ollama) — cambio arquitectónico motivado por las limitaciones de cuota y disponibilidad de los proveedores gratuitos. El agente de reconocimiento se encuentra funcional sobre el modelo local: ejecuta el SPA Crawler y Katana, consolida resultados y genera un plan de ataque priorizado con endpoints, métodos, peticiones estructuradas y herramientas recomendadas. La migración de los agentes de validación y reporte al modelo local, así como la validación del flujo completo entre agentes, se encuentran en desarrollo.

El frontend, desarrollado en Next.js, cuenta con la estructura de componentes necesarios para consumir el backend (paneles de configuración, trazabilidad y reporte, además del hook de conexión por WebSocket), pero su integración funcional con el pipeline multiagente aún no se ha completado. Los pendientes hacia la entrega final incluyen: finalizar la migración del agente de validación al modelo local, integrar y validar el flujo de extremo a extremo entre los cuatro agentes, consolidar la integración frontend-backend, y formalizar la evaluación de resultados sobre el entorno autorizado.

---

## 1. Introducción

El proyecto SECURE aborda una necesidad concreta identificada en el ámbito de la evaluación de seguridad de aplicaciones web: la dificultad que enfrentan estudiantes y desarrolladores al interpretar, organizar y correlacionar la información técnica que generan las herramientas automatizadas de pentesting. En la práctica, estas herramientas producen salidas extensas, heterogéneas y poco estructuradas, lo que incrementa el esfuerzo manual necesario para identificar hallazgos relevantes y comprender su contexto dentro del sistema evaluado.

La propuesta de SECURE se orienta a mejorar esta situación mediante una plataforma multiagente que organiza el flujo de análisis, estructura los hallazgos y los presenta a través de un panel visual trazable. En lugar de reemplazar al evaluador humano, el sistema actúa como una herramienta de asistencia que hace explícito el proceso seguido por los agentes, permitiendo al usuario comprender qué acciones se ejecutaron, con qué herramientas, sobre qué endpoints y con qué evidencia.

El estado actual del proyecto corresponde a una fase de transición técnica: la infraestructura base (RabbitMQ, servidor MCP, ejecución en contenedores efímeros) se encuentra operativa, y el agente de reconocimiento ya funciona sobre el modelo local (Qwen vía Ollama), ejecutando el SPA Crawler y Katana, consolidando resultados y generando el plan de ataque. La migración de los agentes de validación y reporte al modelo local, así como la validación del flujo completo entre los cuatro agentes, se encuentran en desarrollo. El frontend cuenta con la estructura de componentes necesarios para consumir el backend, pero su integración funcional con el pipeline aún no se ha completado.

---

## 2. Marco conceptual

Para comprender la propuesta de SECURE es necesario establecer un conjunto de conceptos técnicos que enmarcan sus decisiones de diseño y su alcance funcional. Estos conceptos provienen de cuatro dominios: ciberseguridad ofensiva, arquitecturas multiagente, protocolos de integración de herramientas con modelos de lenguaje, y prácticas de despliegue aislado.

### 2.1 Evaluación de seguridad web y OWASP Top 10

La evaluación de seguridad de aplicaciones web consiste en un proceso sistemático mediante el cual se identifican, validan y documentan debilidades explotables en un sistema bajo condiciones controladas. Este proceso se apoya en herramientas especializadas que automatizan tareas de reconocimiento, enumeración y explotación, generando información que luego debe ser interpretada por un evaluador humano. Para organizar el universo de vulnerabilidades conocidas, la industria utiliza marcos de referencia como el **OWASP Top 10** (OWASP Foundation, 2025a), que agrupa las categorías de riesgo más críticas en aplicaciones web. Este marco se complementa con la **OWASP Web Security Testing Guide** (OWASP Foundation, 2025b), que documenta metodologías y vectores específicos por categoría. SECURE toma como referencia cuatro categorías: **A05:2025 – Injection**, **A01:2025 – Broken Access Control**, **A07:2025 – Identification and Authentication Failures** y **A04:2025 – Cryptographic Failures**.

Es importante distinguir tres conceptos que suelen mezclarse en la literatura y que SECURE separa explícitamente:

- **Categoría OWASP:** agrupación temática de riesgos (por ejemplo, A05 – Injection).
- **Vector o subcategoría:** tipo específico de vulnerabilidad dentro de una categoría (por ejemplo, SQL Injection, OS Command Injection, XSS).
- **Skill:** herramienta concreta que el sistema ejecuta para validar uno o más vectores (por ejemplo, `sqlmap`, `commix`, `dalfox`).

La relación entre estos tres niveles se documenta en la Sección 3.4, donde se explicita qué vector de qué categoría cubre cada skill.

Para clasificar la severidad de los hallazgos, SECURE utiliza categorías cualitativas alineadas conceptualmente con la escala de severidad de **CVSS v3.1** (FIRST, 2019): CRITICAL, HIGH, MEDIUM, LOW e INFO. El agente de validación asigna una de estas categorías a cada hallazgo confirmado como parte del contrato de datos (`Vulnerability`), y el agente de reportero la incorpora en el informe final junto con la evidencia y el comando reproducible.

### 2.2 Modelos de lenguaje y agentes autónomos

Los **Modelos de Lenguaje de Gran Escala (LLM)** son sistemas entrenados sobre grandes volúmenes de texto que permiten generar, resumir y razonar sobre información en lenguaje natural. Su arquitectura se basa en el mecanismo de **atención** propuesto por Vaswani et al. (2017), y su capacidad de realizar tareas sin reentrenamiento específico se conoce como *few-shot learning* (Brown et al., 2020). En el contexto de la automatización de tareas, los LLM pueden integrarse con herramientas externas para ejecutar acciones concretas, en un patrón conocido como **tool calling** (Zhao et al., 2023). En este patrón, el modelo no solo genera texto, sino que decide qué herramienta invocar, con qué argumentos, y cómo interpretar su resultado.

Un **agente autónomo** en el sentido que utiliza SECURE se define como un componente que mantiene un objetivo, ejecuta un ciclo iterativo de percepción-decisión-acción, y evalúa el resultado de cada acción para decidir el siguiente paso (Russell & Norvig, 2021). En el proyecto, los agentes no son entes aislados, sino integrantes de un **sistema multiagente** en el que cada uno asume un rol especializado y se comunica con los demás mediante mensajes estructurados. Esta división de responsabilidades permite que cada agente reciba un input acotado y entregue un output verificable, en lugar de concentrar todo el razonamiento en un único modelo.

### 2.3 Model Context Protocol (MCP)

El **Model Context Protocol (MCP)** es un estándar abierto propuesto por Anthropic (Anthropic, 2024) que define cómo un modelo de lenguaje puede descubrir y ejecutar herramientas externas de forma estructurada. En lugar de definir manualmente cada herramienta dentro del agente, MCP permite que exista un **servidor de skills** que exponga un catálogo dinámico de capacidades, las describa con un esquema, y las ejecute cuando el agente lo solicite. En SECURE, el servidor MCP es implementado por el componente `skills_controller`, que actúa como intermediario entre los agentes y las herramientas reales de pentesting.

Cada skill se describe mediante un esquema JSON que especifica su nombre, su propósito y los argumentos que acepta. Esto permite que los agentes descubran las capacidades disponibles en tiempo de ejecución y las invoquen sin requerir cambios en su código. El patrón desacopla el razonamiento de la ejecución, facilita la incorporación de nuevas herramientas, y mejora la trazabilidad porque toda invocación pasa por un punto centralizado.

### 2.4 Contenedores efímeros y aislamiento de herramientas

Este enfoque de aislamiento mediante contenedores efímeros es una aplicación directa del modelo de ejecución propuesto por Docker (Docker, 2025), donde cada tarea se ejecuta en un entorno aislado con su propio sistema de archivos, red y límites de recursos.

Las herramientas de pentesting utilizadas por SECURE (SQLMap, DalFox, Commix, Nuclei, FFuF, entre otras) se ejecutan en **contenedores Docker efímeros**. Esto significa que, por cada invocación, el sistema crea un contenedor temporal con la imagen de la herramienta, ejecuta el comando requerido, captura la salida y destruye el contenedor. Este enfoque ofrece tres ventajas principales: **aislamiento** (cada ejecución no interfiere con otras), **reproducibilidad** (la imagen fija la versión de la herramienta) y **seguridad** (no se instalan herramientas directamente en el host).

Adicionalmente, los contenedores se conectan a una red Docker interna que permite que las herramientas alcancen al objetivo sin exponer tráfico al exterior. El sistema aplica además límites de memoria (`mem_limit`) para evitar que una herramienta consuma recursos excesivos, y define códigos de salida aceptados por herramienta para distinguir entre "sin hallazgos" y "error real".

### 2.5 Comunicación asíncrona mediante colas de mensajes

RabbitMQ (RabbitMQ, 2025) es un broker de mensajes que implementa el protocolo **AMQP** y soporta el patrón de comunicación RPC sobre colas descrito por su documentación oficial.

Para coordinar la comunicación entre agentes, SECURE utiliza **RabbitMQ** como broker de mensajes. Cada agente consume de una cola dedicada y responde mediante el patrón **RPC (Remote Procedure Call)** sobre el mismo broker: el emisor publica un mensaje en la cola destino, adjunta un `reply_to` y un `correlation_id`, y espera la respuesta en una cola temporal. Este diseño tiene tres consecuencias arquitectónicas relevantes. Primero, **desacopla temporalmente** a emisor y receptor: si un agente se reinicia, los mensajes pendientes permanecen en la cola. Segundo, **facilita el reemplazo de componentes**: cambiar la implementación de un agente no requiere modificaciones en los demás, solo respetar el contrato de mensajes. Tercero, **mejora la resiliencia**: los fallos parciales se aíslan en una cola y no se propagan a todo el sistema.

### 2.6 Rastreo de aplicaciones SPA y captura de peticiones

El SPA Crawler de SECURE está construido sobre **Playwright** (Microsoft, 2025), una librería de automatización de navegadores que permite controlar Chromium, Firefox y WebKit de forma programática, y que resulta adecuada para este tipo de aplicaciones porque ejecuta el JavaScript de la página antes de extraer su contenido.

Muchas aplicaciones web modernas son **Single Page Applications (SPA)** construidas con frameworks como Angular, React o Vue. Estas aplicaciones presentan un desafío particular para las herramientas tradicionales de crawleo, porque sus rutas son gestionadas en el cliente mediante fragmentos de URL (`#/login`) o mediante navegación dinámica, y no aparecen como enlaces HTML navegables. Para abordar este desafío, SECURE incorpora un **SPA Crawler** basado en Playwright, que abre un navegador headless, navega por la aplicación, descubre rutas dinámicas y **captura las peticiones HTTP completas** (método, headers, body) que genera la SPA al interactuar con sus formularios.

Las peticiones capturadas se almacenan como archivos `.req` en un volumen compartido, y posteriormente son utilizadas por las herramientas de validación que requieren la petición completa (como SQLMap con `-r` o Commix con `-r`) en lugar de una simple URL. Este mecanismo resuelve una limitación fundamental de las herramientas tradicionales: la incapacidad de atacar endpoints que reciben parámetros por POST con cuerpos JSON.

### 2.7 Trazabilidad y contratos de datos

Finalmente, SECURE adopta un enfoque de **contratos de datos estrictos** para toda comunicación entre agentes. Los mensajes no son texto libre, sino objetos validados mediante **Pydantic** (Pydantic, 2025), una librería de Python que permite declarar esquemas con tipos, validaciones y estructuras anidadas, y que genera errores claros cuando un objeto no cumple el contrato esperado. Esto garantiza que un agente no pueda entregar un resultado inválido al siguiente, y permite además registrar trazabilidad completa de cada fase: qué se descubrió, qué se probó, con qué herramienta, con qué evidencia y con qué nivel de confianza. La trazabilidad se expone al usuario a través del panel visual y se incluye en el informe final.

---

## 3. Planteamiento del problema

### 3.1 Descripción del problema

En los flujos de auditoría y análisis de seguridad en aplicaciones web, la experiencia operativa presenta dificultades relacionadas con la organización, interpretación y correlación de la información obtenida. Estas dificultades afectan principalmente a estudiantes y desarrolladores que se aproximan por primera vez a tareas de evaluación de seguridad, y que no cuentan con la experiencia necesaria para filtrar grandes volúmenes de salida técnica.

Tres problemas específicos se identifican:

1. **Complejidad en la interpretación de resultados.** Herramientas como SQLMap, Nuclei o ZAP generan cientos de líneas de salida técnica con hallazgos heterogéneos, advertencias y falsos positivos mezclados. Sin un mecanismo de filtrado y clasificación preliminar, el usuario debe interpretar manualmente cada resultado, lo cual incrementa el tiempo de análisis y el riesgo de omitir hallazgos relevantes.

2. **Limitada visibilidad del flujo de análisis.** Cuando el proceso involucra varias herramientas, el usuario no puede reconstruir fácilmente qué acciones se ejecutaron, en qué orden, con qué argumentos y por qué motivo. Esta falta de trazabilidad dificulta la validación del proceso y reduce la confianza en los resultados.

3. **Presencia de alertas imprecisas y no correlacionadas.** Las herramientas automatizadas generan alertas que requieren revisión posterior para determinar su relevancia en el contexto del entorno evaluado. Sin un mecanismo de correlación, el usuario recibe hallazgos aislados que no puede relacionar entre sí ni con el resto del análisis.

### 3.2 Usuarios y necesidad verificable

El usuario principal de SECURE es un **estudiante de ciberseguridad o desarrollo de software** que realiza prácticas de evaluación en entornos de laboratorio autorizados. Este usuario necesita: (a) comprender de forma estructurada qué acciones se ejecutaron durante la evaluación, (b) recibir un conjunto reducido y priorizado de hallazgos con evidencia, (c) contar con información suficiente para comprender el contexto de cada hallazgo, y (d) disponer de un informe revisable que pueda ser validado por un tutor o evaluador humano.

Usuarios secundarios incluyen a **desarrolladores de software** que buscan identificar debilidades en aplicaciones propias en entornos de prueba, y **evaluadores o tutores académicos** que revisan el flujo de análisis y los resultados generados para fines de validación formativa.

### 3.3 Restricciones y supuestos de diseño

- **Entorno de aplicación:** el prototipo opera exclusivamente sobre aplicaciones disponibles en entornos de laboratorio o de prueba autorizados. La validación se realiza sobre **OWASP Juice Shop**, una aplicación deliberadamente vulnerable diseñada para fines educativos.
- **Marco ético:** queda excluido el desarrollo de código malicioso, la evasión de mecanismos de defensa en entornos no autorizados, y la ejecución de pruebas sobre infraestructura de producción sin permiso explícito.
- **Alcance de análisis:** la biblioteca de skills se limita a un conjunto acotado y representativo que cubre cuatro categorías del OWASP Top 10: Inyección (A05), Control de Acceso Roto (A01), Fallos de Autenticación (A07) y Fallos Criptográficos (A04).
- **Alcance de automatización:** la plataforma asiste y organiza el proceso de análisis, sin plantear explotación autónoma ni pruebas ofensivas no supervisadas. Las acciones se ejecutan sobre el entorno autorizado y dentro de un alcance definido.
- **Desempeño del modelo:** los resultados generados con apoyo de modelos de lenguaje se consideran apoyo al análisis y no sustituto de la validación humana.

### 3.4 Alcance actualizado

El MVP comprometido incluye:

1. Arquitectura multiagente con cuatro agentes especializados (orquestador, reconocimiento, validación y reporte).
2. **Nueve skills de ciberseguridad implementados vía MCP**, agrupados por función:
   - **Reconocimiento:** `katana_full`, `spa_crawler`, `deep_crawler`.
   - **Descubrimiento de superficie:** `ffuf`.
   - **Validación de vulnerabilidades:** `sqlmap`, `commix`, `dalfox`, `nuclei`, `jwt_tool`.

3. **Cobertura de cuatro categorías del OWASP Top 10**, con la siguiente trazabilidad explícita entre categoría, vector específico y skill responsable de su validación:

   | Categoría OWASP | Vector / Subcategoría | Skill(s) responsable(s) |
   |-----------------|------------------------|--------------------------|
   | **A05:2025 – Injection** | SQL Injection | `sqlmap` |
   | **A05:2025 – Injection** | OS Command Injection | `commix` |
   | **A05:2025 – Injection** | Cross-Site Scripting (XSS reflejado) | `dalfox` |
   | **A01:2025 – Broken Access Control** | Exposición de información sensible (configs, memoria, rutas), IDOR, directorios ocultos | `nuclei` (con `ffuf` como descubridor de rutas previas) |
   | **A07:2025 – Identification and Authentication Failures** | JWT mal configurado (alg:none, key confusion, weak secret), credenciales por defecto, bypass de autenticación | `jwt_tool` + `nuclei` |
   | **A04:2025 – Cryptographic Failures** | Headers de seguridad ausentes, configuraciones TLS/SSL débiles | `nuclei` |

   **Nota metodológica:** las cuatro categorías del alcance son cubiertas con un enfoque de **cobertura superpuesta**: `nuclei` actúa como escáner multivectorial (A01, A07, A04) ajustando su comportamiento mediante el parámetro `tags`, mientras que `jwt_tool` complementa A07 con análisis específico de JSON Web Tokens. Las tres skills de reconocimiento (`katana_full`, `spa_crawler`, `deep_crawler`) no ejecutan ataques: alimentan la fase de reconocimiento que provee los endpoints a validar. Adicionalmente, `ffuf` no es una herramienta de ataque, sino de descubrimiento de superficie: sus hallazgos (rutas ocultas, archivos expuestos) alimentan tanto al escáner multivectorial (`nuclei`) como a los skills de validación específicos (`sqlmap`, `commix`, `dalfox`).
4. Registro estructurado de la trazabilidad de cada fase del análisis.
5. Generación de informe técnico en Markdown con evidencia, severidad preliminar y comandos reproducibles.
6. Validación sobre OWASP Juice Shop como entorno autorizado de referencia.

**Fuera del alcance:** explotación autónoma de vulnerabilidades, pruebas en producción, evasión de mecanismos de defensa, y cobertura exhaustiva de todas las categorías del OWASP Top 10.

---

## 4. Objetivos

### 4.1 Objetivo general

Diseñar e implementar un prototipo funcional de sistema multiagente basado en MCP que asista la detección y validación de vulnerabilidades web en entornos de laboratorio autorizados, generando informes estructurados con trazabilidad completa del proceso de análisis.

### 4.2 Objetivos específicos

Reformulados como resultados demostrables:

1. **Diseñar** una arquitectura de cuatro agentes especializados (orquestador, reconocimiento, validación y reporte) que se comuniquen mediante colas de mensajes asíncronas y colaboren en la ejecución de un flujo de auditoría acotado.
2. **Integrar** nueve skills de ciberseguridad (`katana_full`, `spa_crawler`, `deep_crawler`, `sqlmap`, `dalfox`, `commix`, `nuclei`, `ffuf`, `jwt_tool`) mediante MCP, de modo que los agentes puedan descubrirlos dinámicamente y ejecutarlos en contenedores Docker efímeros.
3. **Cubrir** cuatro categorías del OWASP Top 10 en el MVP: Inyección (A05), Control de Acceso Roto (A01), Fallos de Autenticación (A07) y Fallos Criptográficos (A04).
4. **Registrar** evidencia estructurada de cada prueba ejecutada, incluyendo endpoint, herramienta utilizada, argumentos, salida y nivel de confianza, mediante contratos de datos validados.
5. **Generar** un informe técnico revisable por el usuario, que incluya clasificación preliminar de severidad, evidencia de cada hallazgo, comando reproducible y recomendación de mitigación.
6. **Validar** el funcionamiento del sistema sobre OWASP Juice Shop como entorno autorizado, verificando que el flujo completo de análisis se ejecute de extremo a extremo una vez completada la migración de los cuatro agentes al modelo local (objetivo actualmente en proceso).
7. **Exponer** la trazabilidad del análisis a través de un panel visual que permita al usuario reconstruir las acciones, decisiones y resultados de cada agente.

---

## 5. Estado del arte / soluciones relacionadas

La evaluación automatizada de seguridad web con apoyo de modelos de lenguaje ha experimentado un crecimiento significativo en los últimos años. Distintas propuestas —comerciales y de código abierto— han explorado el uso de LLM para tareas de pentesting, con distintos énfasis: algunas priorizan la cobertura de herramientas, otras la autonomía del agente, y otras la calidad del reporte final. A continuación se resumen las más relevantes y se posiciona SECURE frente a ellas.

### 5.1 Soluciones existentes

**Plataformas comerciales**

- **CSI (Cyber Security Intelligence)** (Cyber Security Intelligence, 2025) es una plataforma comercial que ofrece servicios de *Vulnerability Assessment & Pen Testing* bajo una metodología *Risk-Based Penetration Assessment (RBPA)*, y declara el uso de agentes de IA para identificar y neutralizar amenazas. Su enfoque está orientado a la gestión continua de vulnerabilidades en producción. Su código, arquitectura interna y metodología detallada no son públicos, lo que impide auditar cómo toman decisiones sus componentes y dificulta la comparación funcional directa con frameworks open-source.

**Herramientas de código abierto**

- **Strix** (Strix, 2025) es un framework open-source de agentes autónomos de pentesting. Su repositorio oficial documenta la ejecución de cadenas de herramientas ofensivas con mínima intervención humana. Su foco está en la autonomía completa del pipeline, mientras que SECURE prioriza la trazabilidad y la estructura del reporte.
- **Shannon** (Shannon, 2024) es un pentester de IA orientado a aplicaciones web y APIs. Su repositorio describe un flujo que integra LLM para planificar ataques y ejecutar herramientas, sin énfasis explícito en la visualización del flujo de análisis ni en la revisión humana del proceso.
- **PentestGPT** (Deng et al., 2023) es una herramienta basada en LLM que asiste al pentester humano en la planificación de ataques. El paper original la describe como una herramienta conversacional de asistencia, no como un pipeline multiagente con trazabilidad estructurada.

### 5.2 Oportunidades de mejora identificadas

Del análisis de las propuestas anteriores se identifican dos oportunidades de mejora que orientan el diseño de SECURE:

1. **Mejora de la experiencia de usuario mediante una interfaz gráfica estructurada.** La mayoría de herramientas del dominio operan exclusivamente por consola: la interpretación y lectura de los reportes se vuelve tediosa y requiere familiaridad con las salidas de cada herramienta. SECURE propone una interfaz web que estructura los resultados en paneles legibles, integrando ayudas visuales que facilitan la comprensión de la severidad de cada hallazgo sin depender de la consola.

2. **Transparencia mediante registro y trazabilidad del flujo de los agentes.** Para auditorías de seguridad confiables, no basta con conocer el resultado final: es indispensable comprender el procedimiento seguido. SECURE incorpora trazabilidad estructurada de cada acción, decisión y resultado de los agentes, permitiendo al usuario reconstruir el flujo de análisis y verificar la procedencia de cada hallazgo.

### 5.3 Posicionamiento de SECURE

SECURE se posiciona como una **plataforma de asistencia al análisis** que prioriza dos elementos poco enfatizados en las soluciones existentes: **trazabilidad del flujo multiagente** y **presentación estructurada del resultado final**.

| Aspecto | CSI | Strix | Shannon | PentestGPT | **SECURE** |
|---------|------------------------|-------|---------|------------|------------|
| Enfoque | Empresarial | Autónomo ofensivo | Web/APIs | Asistencia conversacional | **Asistencia con trazabilidad** |
| Interfaz | Web comercial | CLI | CLI | Conversacional | **Web con paneles** |
| Trazabilidad del flujo | Limitada | Parcial | Limitada | Baja | **Estructurada por fase** |
| Ejecución aislada de herramientas | No público | No público | Parcial | No | **Contenedores efímeros** |
| Explotación autónoma | Sí | Sí | Parcial | No | **Fuera de alcance** |
| Enfoque académico / formativo | No | No | No | Parcial | **Sí** |

La propuesta de SECURE **no compite** con soluciones comerciales de pentesting ofensivo, ni pretende reemplazar al evaluador humano. Su aporte se centra en:

- **Diseño de una arquitectura multiagente con trazabilidad explícita**, donde cada fase del análisis queda documentada como un objeto de datos verificable.
- **Integración de herramientas reales de pentesting en contenedores efímeros**, ejecutados desde un servidor MCP que desacopla el descubrimiento de herramientas de su ejecución.
- **Aplicación de un enfoque formativo**: la plataforma está orientada a estudiantes y desarrolladores que necesitan comprender el flujo de un análisis de seguridad, más que a equipos ofensivos que buscan autonomía total.
- **Cobertura acotada y explícita** de cuatro categorías del OWASP Top 10, con nueve skills especializados, en lugar de una cobertura exhaustiva de baja profundidad.

Del análisis anterior se deriva explícitamente la necesidad de una solución que combine cuatro características que las propuestas existentes no reúnen simultáneamente: (1) **trazabilidad estructurada** de cada fase del análisis, de modo que el usuario pueda reconstruir la cadena de decisiones; (2) **presentación visual** de los resultados en una interfaz web, en lugar de una consola con salida cruda; (3) **ejecución aislada** de herramientas mediante contenedores efímeros, con evidencia reproducible; y (4) un **enfoque formativo** que priorice la comprensión del flujo por sobre la autonomía total del sistema. Ninguna de las soluciones revisadas reúne estas cuatro características simultáneamente: las comerciales no son auditables, las de código abierto priorizan la autonomía, y ninguna está orientada explícitamente a un contexto académico de aprendizaje. SECURE responde a estas necesidades mediante una arquitectura multiagente que hace explícito el flujo de análisis, ejecuta herramientas reales en entornos aislados, y presenta el resultado en un panel revisable por un evaluador humano.

Adicionalmente, el proyecto documenta **decisiones arquitectónicas derivadas de fallos reales observados durante el desarrollo** —como la migración de LLM en la nube a un modelo local, o la implementación de dos capas de resiliencia para manejar errores del modelo— lo cual diferencia a SECURE de prototipos que solo demuestran integración de herramientas sin reflexionar sobre su robustez operativa.

---

## 6. Solución propuesta

### 6.1 Descripción general

SECURE es una plataforma web de evaluación asistida de seguridad que combina cuatro componentes principales: (1) una arquitectura multiagente que coordina el flujo de análisis, (2) una capa MCP que expone skills especializados de ciberseguridad, (3) un motor de ejecución que lanza herramientas reales de pentesting en contenedores efímeros, y (4) una interfaz gráfica que presenta la trazabilidad y los resultados del análisis.

La plataforma no reemplaza al evaluador humano. Su propósito es reducir el esfuerzo manual asociado a la interpretación de resultados, estructurar la información obtenida de múltiples herramientas, y hacer visible el flujo de análisis seguido por los agentes. El resultado final es un informe técnico revisable, con hallazgos priorizados y evidencia verificable.

### 6.2 Usuarios objetivo

- **Estudiante de ciberseguridad o desarrollo:** usuario principal. Utiliza la plataforma para realizar prácticas de evaluación sobre aplicaciones de laboratorio y comprender el flujo de un análisis de seguridad de forma asistida.
- **Desarrollador de software:** utiliza la plataforma para identificar debilidades en aplicaciones propias en entornos de prueba, con el objetivo de corregirlas antes de su despliegue.
- **Evaluador o tutor académico:** utiliza la información estructurada del sistema para revisar el flujo de análisis y validar los resultados generados.

### 6.3 Propuesta de valor

La propuesta de valor de SECURE se articula en tres ejes:

1. **Organización y estructuración de resultados.** En lugar de presentar salidas crudas de herramientas, el sistema genera un informe estructurado con hallazgos clasificados, evidencia, severidad preliminar y comandos reproducibles.
2. **Trazabilidad del flujo de análisis.** Cada fase del pipeline (reconocimiento, validación, reporte) queda registrada con sus entradas, salidas y decisiones asociadas, permitiendo al usuario reconstruir el proceso completo.
3. **Integración modular de herramientas mediante MCP.** El catálogo de skills se expone dinámicamente, permitiendo incorporar nuevas herramientas sin modificar el código de los agentes.

### 6.4 Arquitectura de la solución

El sistema se organiza en cuatro capas:

**Capa de entrada (API Gateway).** Recibe peticiones HTTP del frontend con la URL objetivo y los parámetros del análisis. Genera un identificador único de tarea y publica el evento en la cola del orquestador.

**Capa de orquestación.** Un agente orquestador coordina la ejecución secuencial de tres agentes especializados: reconocimiento, validación y reporte. El orquestador no ejecuta herramientas directamente; delega cada fase al agente correspondiente y consolida el resultado final.

**Capa de agentes especializados.**
- **Agente de reconocimiento:** analiza la superficie del objetivo, ejecuta el SPA Crawler y Katana, y produce un plan de ataque priorizado con endpoints, métodos, parámetros y archivos de petición asociados.
- **Agente de validación:** recibe el plan y ejecuta las herramientas de validación correspondientes (SQLMap, DalFox, Commix, Nuclei, FFuF) sobre cada endpoint priorizado, generando hallazgos con evidencia y comandos reproducibles.
- **Agente de reporte:** consolida los datos de reconocimiento y validación en un informe Markdown estructurado con severidad, evidencia y mitigaciones.
- **Trazabilidad de skills a categorías OWASP.** El catálogo MCP no expone las skills como herramientas genéricas, sino como capacidades asociadas a un vector específico. La siguiente tabla resume esta asignación, que es la que gobierna la selección de herramientas en la fase de validación:

| Categoría OWASP | Vector validado | Skill ejecutada | Fase del pipeline |
|-----------------|-----------------|------------------|--------------------|
| A05:2025 – Injection | SQL Injection | `sqlmap` | Validación |
| A05:2025 – Injection | OS Command Injection | `commix` | Validación |
| A05:2025 – Injection | XSS reflejado | `dalfox` | Validación |
| A01:2025 – BAC | Exposures / IDOR / rutas ocultas | `nuclei` (+ `ffuf`) | Validación |
| A07:2025 – Auth Failures | JWT (alg:none, key confusion, weak secret) | `jwt_tool` | Validación |
| A07:2025 – Auth Failures | Default logins / auth bypass | `nuclei` | Validación |
| A04:2025 – Crypto Failures | Headers / TLS / SSL | `nuclei` | Validación |
| — | Reconocimiento de superficie | `katana_full`, `spa_crawler` | Reconocimiento |
| — | Análisis profundo de formularios y peticiones | `deep_crawler` | Reconocimiento |

Esta tabla es la que el agente orquestador consulta para decidir qué skill invocar en cada caso. A diferencia de un diseño donde el LLM decide libremente qué herramienta usar, SECURE aplica una política determinista basada en el tipo de auditoría solicitado. La fase de reconocimiento se ejecuta en dos niveles: `katana_full` y `spa_crawler` corren siempre para mapear la superficie; `deep_crawler` se activa únicamente cuando el vector objetivo lo requiere (por ejemplo, SQL Injection necesita peticiones HTTP completas con body y headers para alimentar a `sqlmap`).

**Capa de ejecución (Skills Controller / MCP).** El servidor MCP expone el catálogo de skills y ejecuta cada invocación lanzando un contenedor Docker efímero con la herramienta correspondiente. Los resultados se normalizan y se devuelven al agente solicitante.

### 6.5 Funcionamiento general

1. **Configuración.** El usuario proporciona la URL de una aplicación objetivo disponible en un entorno autorizado (por ejemplo, `http://juice-shop:3000`) y selecciona el tipo de análisis a ejecutar.
2. **Análisis.** El orquestador delega la fase de reconocimiento, que ejecuta el SPA Crawler y Katana para descubrir endpoints, rutas y peticiones. Los artefactos capturados se almacenan en un volumen compartido.
3. **Validación.** El agente de validación analiza el plan de reconocimiento, selecciona las herramientas adecuadas para cada vector, y las ejecuta contra los endpoints priorizados. Cada hallazgo se registra con evidencia y comando reproducible.
4. **Reporte.** El agente de reporte consolida toda la información y genera un informe Markdown con hallazgos, severidad, evidencia y recomendaciones.
5. **Visualización.** El usuario consulta el progreso y el resultado final desde la interfaz gráfica, que presenta la trazabilidad del flujo y el informe generado.

### 6.6 Relación con el problema y el alcance

La solución responde a los tres problemas identificados en el planteamiento mediante mecanismos concretos y verificables:

**Reducción de la complejidad de interpretación.** El agente de validación no entrega al usuario la salida cruda de cada herramienta, sino que aplica tres filtros sucesivos antes de persistir un hallazgo: (1) descarta URLs sin parámetros inyectables, (2) descarta recursos estáticos mediante una lista de extensiones, y (3) exige evidencia textual (error de base de datos, payload reflejado, cambio de tiempo de respuesta) para confirmar una vulnerabilidad. Los artefactos temporales (archivos `.req` con peticiones HTTP completas) se generan y consumen dentro de la misma invocación del handler; no se persisten ni se exponen al usuario. Como resultado, el informe final contiene únicamente hallazgos con evidencia verificable, no la salida cruda completa.

**Mejora de la visibilidad del flujo.** Cada invocación a una skill produce un objeto de trazabilidad (`SkillInvocation`) que registra: el skill invocado, los argumentos utilizados, la duración, el código de salida y un resumen de la salida. Estos objetos se persisten en un volumen compartido y se exponen al usuario a través del panel de trazabilidad, permitiéndole reconstruir la secuencia completa de acciones ejecutadas.

**Correlación de hallazgos.** El agente de validación recibe del agente de reconocimiento un plan de ataque priorizado, con endpoints, métodos, parámetros y peticiones estructuradas. El agente de reconocimiento filtra previamente la superficie descubierta por los crawlers y pasa únicamente los endpoints relevantes al vector objetivo. Cada hallazgo se asocia al `target_id` que lo originó, de modo que el informe final permite trazar la cadena completa: *endpoint descubierto → prueba ejecutada → evidencia observada → hallazgo reportado*. Esta cadena evita la presentación de hallazgos aislados y permite al usuario evaluar la relevancia de cada resultado en el contexto del análisis completo.

El alcance del MVP se limita a los nueve skills mencionados, cuatro categorías del OWASP Top 10, un entorno de validación autorizado (Juice Shop) y una plataforma de asistencia al análisis sin explotación autónoma.

---

## 7. Metodología de desarrollo

Ver detalle completo en el [Primer Informe](./PrimerInforme.md#7-metodología-de-desarrollo-y-plan-de-trabajo).

El proyecto sigue una metodología de **prototipado iterativo e incremental**, con sprints semanales, reuniones de tutoría y sesiones presenciales de sincronización. Las iteraciones más recientes se han centrado en estabilizar el pipeline multiagente, migrar a modelo local, y consolidar la captura de peticiones SPA.

---

## 8. Requerimientos

### 8.1 Funcionales

| ID | Requerimiento | Estado |
|----|---------------|--------|
| RF-01 | Recibir URL objetivo desde el frontend y encolar tarea de análisis | ✅ Implementado |
| RF-02 | Ejecutar reconocimiento automatizado de endpoints (SPA Crawler, Katana) | ✅ Implementado (funcional sobre modelo local) |
| RF-03 | Capturar peticiones HTTP completas (`.req`) para POST/JSON | ✅ Implementado |
| RF-04 | Ejecutar validación de SQL Injection (SQLMap) | 🔧 Skill implementado y validado; integración en el agente pendiente de migración |
| RF-05 | Ejecutar validación de XSS (DalFox) | 🔧 Skill implementado; integración en el agente pendiente de migración |
| RF-06 | Ejecutar validación de Command Injection (Commix) | 🔧 Skill implementado; integración en el agente pendiente de migración |
| RF-07 | Ejecutar validación multivectorial (Nuclei) | 🔧 Skill implementado; integración en el agente pendiente de migración |
| RF-08 | Ejecutar fuzzing de rutas y parámetros (FFuF) | 🔧 Skill implementado; integración en el agente pendiente de migración |
| RF-09 | Generar informe técnico en Markdown con evidencia y severidad | 🔧 Reporter implementado; migración al modelo local pendiente |
| RF-10 | Exponer trazabilidad estructurada del flujo de análisis | ✅ Implementado (backend) |
| RF-11 | Presentar resultados en panel visual interactivo | 🔧 Estructura frontend lista; integración pendiente |
| RF-12 | Registrar evidencia verificable de cada prueba ejecutada | ✅ Implementado (persistencia de artefactos) |

### 8.2 No funcionales

| ID | Requerimiento | Criterio |
|----|---------------|----------|
| RNF-01 | Seguridad del entorno de ejecución | Contenedores efímeros aislados en red interna |
| RNF-02 | Trazabilidad | Registro estructurado de cada acción y resultado |
| RNF-03 | Extensibilidad | Nuevas skills sin modificar código de agentes (MCP) |
| RNF-04 | Tolerancia a fallos | Arquitectura multiagente con colas durables |
| RNF-05 | Reproducibilidad | Imágenes Docker versionadas por herramienta |
| RNF-06 | Usabilidad | Interfaz gráfica estructurada con trazabilidad visual |
| RNF-07 | Mantenibilidad | Contratos Pydantic y separación de responsabilidades |

---

## 9. Evaluación de alternativas

Durante el diseño de SECURE se evaluaron distintas alternativas tecnológicas para los componentes críticos del sistema. A continuación se documentan las decisiones más relevantes, los criterios de comparación utilizados y la justificación de la opción seleccionada.

### 9.1 Pregunta 1: ¿Cuál alternativa ofrece mejor desempeño bajo carga esperada?

**Criterios de comparación y escenario de medición.** Las alternativas se comparan bajo el siguiente escenario de referencia: un pipeline de reconocimiento + validación sobre Juice Shop, con *N*=5 tareas concurrentes, midiendo (a) tiempo de respuesta por fase en segundos, (b) tareas completadas sin fallo, (c) reintentos por tarea, y (d) recuperación tras detener un agente a mitad de ejecución. Los valores de la tabla corresponden a las propiedades documentadas por cada tecnología y se marcan como `[medido]` (si se obtuvo en el entorno del proyecto) o `[documentado]` (si proviene de la documentación oficial).

**Alternativas evaluadas:**

| Alternativa | Tiempo de respuesta por fase | Throughput concurrente | Recuperación ante fallo de agente | Fuente del dato |
|-------------|------------------------------|------------------------|-------------------------------------|-----------------|
| HTTP directo | Bajo (<1 s) | Limitado por número de hilos del cliente | Reinicio manual completo | [documentado] RFC 7230 |
| RabbitMQ (seleccionada) | Medio (2–5 s por RPC) | Alto (prefetch + colas durables) | Recuperación automática al reiniciar consumidor | [documentado] RabbitMQ, 2025; [medido] tiempo de RPC del Orquestador (Sección 13) |
| gRPC | Muy bajo (<500 ms) | Muy alto (multiplexing HTTP/2) | Requiere reconexión del canal | [documentado] gRPC docs |

**Justificación:** se seleccionó RabbitMQ por tres razones. Primero, la naturaleza del pipeline es **asíncrona y secuencial**: cada fase puede tardar minutos (reconocimiento con SPA Crawler, validación con SQLMap), por lo que la latencia absoluta no es el criterio dominante. Segundo, RabbitMQ ofrece **tolerancia a fallos temporales** mediante colas durables: si un agente se reinicia, las tareas pendientes permanecen en la cola y se procesan al volver. Tercero, el desacoplamiento temporal permite que cada agente escale de forma independiente. gRPC habría ofrecido mejor rendimiento pero a costa de mayor rigidez en los contratos y menor tolerancia a fallos parciales. Los criterios de comparación se derivan del patrón RPC documentado por RabbitMQ (RabbitMQ, 2025) y de las características técnicas publicadas para el protocolo AMQP. La justificación de la selección no se basa únicamente en etiquetas cualitativas: la tolerancia a fallos de RabbitMQ está respaldada por su soporte de colas durables, y el desacoplamiento temporal está documentado como una propiedad del patrón de mensajería asíncrona (RabbitMQ, 2025).

### 9.2 Pregunta 2: ¿Qué grado de acoplamiento introduce cada opción?

**Criterios de comparación:** dependencia de servicios externos, interdependencia entre módulos internos, facilidad de sustitución de componentes.

**Alternativas evaluadas para el modelo de lenguaje:**

| Alternativa | Dependencia externa | Interdependencia | Sustituibilidad |
|-------------|---------------------|------------------|-----------------|
| LLM en la nube (Groq, Gemini) | Alta (API externa, cuotas) | Media (SDK específico por proveedor) | Limitada |
| **LLM local (Qwen vía Ollama) — seleccionada** | **Ninguna** | **Baja (API compatible OpenAI)** | **Alta** |
| Múltiples proveedores conmutados | Alta | Alta (lógica de fallback) | Media |

**Justificación:** durante el desarrollo se implementó inicialmente una arquitectura basada en proveedores en la nube (Groq) con dos cuentas y cuatro modelos distintos, con el objetivo de sortear las limitaciones de cuota. Sin embargo, esta estrategia introdujo tres problemas recurrentes: (1) **rate limits** que provocaban errores 429 durante las fases críticas, (2) **inconsistencia en el soporte de tool calling** entre modelos, y (3) **dependencia de servicios externos** con latencia variable. La migración a un **modelo local (Qwen 2.5 servido vía Ollama)** eliminó las cuotas, garantizó la disponibilidad del servicio, y redujo el acoplamiento con SDKs específicos, ya que Ollama expone una API compatible con OpenAI. Esta decisión se documenta como uno de los cambios arquitectónicos más relevantes del proyecto.
Las limitaciones de los proveedores en la nube (rate limits, inconsistencias en soporte de tool calling) están documentadas de forma general en la literatura sobre despliegue de LLM en producción (Zhao et al., 2023). Ollama, por su parte, expone una API compatible con OpenAI (Ollama, 2025), lo que facilita la sustitución de proveedores sin cambios en el código de los agentes.

**Datos observados durante la migración.** Los siguientes datos se obtuvieron durante el desarrollo del proyecto antes y después de la migración:

| Métrica | Con proveedores en la nube (Groq) | Con modelo local (Qwen vía Ollama) |
|---------|------------------------------------|-------------------------------------|
| Errores 429 (rate limit) por sesión de auditoría | 1 a 3+ por sesión de validación | 0 |
| Tasa de tool calling válido | Inconsistente entre modelos | Estable |
| Dependencia de servicio externo | Sí (API key, cuota) | No |
| Latencia por llamada | Variable (500 ms – 3 s) | Constante (~1–2 s en hardware local) |

Estos datos se registraron a partir de los logs de los agentes durante las iteraciones de desarrollo (Sección 13) y respaldan cuantitativamente la decisión de migrar al modelo local.

**Alternativas evaluadas para la integración de herramientas:**

| Alternativa | Acoplamiento | Facilidad de extensión |
|-------------|--------------|----------------------|
| Integración directa (import de módulos) | Alto | Baja |
| **Servidor MCP con catálogo declarativo (seleccionada)** | **Bajo** | **Alta** |
| Ejecución vía scripts individuales | Medio | Media |

**Justificación:** el patrón MCP desacopla el descubrimiento de herramientas de su ejecución. Los agentes no conocen las herramientas por import directo, sino que las descubren mediante una consulta al catálogo del servidor MCP. Esto permite añadir nuevas skills sin modificar el código de los agentes. 

### 9.3 Pregunta 3: ¿Qué nivel de disponibilidad y tolerancia a fallos ofrece cada alternativa?

**Criterios de comparación:** uptime esperado, mecanismos de recuperación ante fallos, impacto de fallos parciales.

**Alternativas evaluadas:**

| Alternativa | Uptime | Recuperación | Impacto de fallo parcial |
|-------------|--------|--------------|--------------------------|
| Pipeline monolítico (todo en un proceso) | Bajo | Reinicio completo | Sistema inoperable |
| **Arquitectura multiagente con colas (seleccionada)** | **Alto** | **Reintentos y colas durables** | **Fallos aislados por agente** |
| Arquitectura serverless | Muy alto | Automática | Dependiente del proveedor |

**Justificación:** se seleccionó la arquitectura multiagente por su capacidad de aislar fallos. Cada agente corre en su propio contenedor; si uno falla, los demás permanecen operativos y los mensajes dirigidos a él se acumulan en la cola hasta que se recupere. Adicionalmente, durante el desarrollo se implementaron tres capas de resiliencia específicas para manejar errores del modelo de lenguaje: (1) una herramienta de finalización explícita (submit tool) que canaliza la entrega del resultado por un canal controlado, evitando que el modelo invente nombres de herramientas o devuelva el JSON por un canal incorrecto —problema observado con los proveedores en la nube durante la primera fase del proyecto; (2) una capa de recovery que recupera resultados válidos incluso cuando el modelo entrega el JSON por un canal incorrecto; y (3) un fallback por regex que extrae endpoints de las salidas crudas de las herramientas si las capas anteriores fallan. Estas capas surgieron de fallos reales observados durante el desarrollo y se documentan como decisiones clave para la robustez operativa del sistema.

**Criterio de medición.** La superioridad en tolerancia a fallos se mide mediante un escenario reproducible: detener un agente durante la ejecución de una tarea y observar (a) si los mensajes pendientes se preservan en la cola, (b) si el agente se reincorpora sin pérdida de estado, y (c) si la tarea completa continúa. Bajo este criterio, la arquitectura de colas durables garantiza preservación de mensajes (documentado por RabbitMQ, 2025), mientras que un pipeline monolítico requeriría reinicio completo del proceso.

**Alternativa descartada: pipeline monolítico.** Se evaluó la posibilidad de implementar todo el flujo en un único proceso con llamadas directas entre funciones. Fue descartada porque: (a) un fallo en cualquier fase bloquea el sistema completo, (b) la escalabilidad horizontal requeriría replicar el proceso completo, y (c) el acoplamiento entre fases dificultaría la sustitución de componentes individuales. La estrategia de ejecución en contenedores efímeros se apoya en el modelo de aislamiento de Docker (Docker, 2025), y los límites de memoria por contenedor se configuran siguiendo las recomendaciones de su documentación.

### 9.4 Resumen de decisiones arquitectónicas

| Componente | Alternativa seleccionada | Criterio dominante |
|------------|--------------------------|--------------------|
| Comunicación entre agentes | RabbitMQ | Tolerancia a fallos y desacoplamiento temporal |
| Modelo de lenguaje | Qwen local vía Ollama | Eliminación de cuotas y disponibilidad |
| Integración de herramientas | Servidor MCP | Desacoplamiento y extensibilidad |
| Ejecución de herramientas | Contenedores Docker efímeros | Aislamiento y reproducibilidad |
| Contratos de datos | Pydantic | Validación estricta y trazabilidad |
| Captura de tráfico SPA | SPA Crawler con Playwright | Capacidad de atacar endpoints POST con JSON |


---

## 10. Diseño y arquitectura

### 10.1 Descripción general de la arquitectura

SECURE sigue una arquitectura **de microservicios orientada a eventos**, con comunicación asíncrona mediante colas de mensajes y ejecución de herramientas en contenedores aislados. La arquitectura se organiza en capas funcionales que separan claramente la recepción de peticiones, la coordinación, la ejecución de herramientas y la presentación de resultados. El enfoque general prioriza el desacoplamiento entre componentes y la trazabilidad de cada fase.

### 10.2 Componentes del sistema

| Componente | Responsabilidad |
|------------|-----------------|
| API Gateway | Recepción de peticiones HTTP, generación de task_id, publicación en cola |
| Orquestador | Coordinación secuencial de agentes, consolidación de resultados |
| Agente de Reconocimiento | Análisis de superficie, captura de peticiones, plan de ataque |
| Agente de Validación | Ejecución de skills sobre endpoints priorizados |
| Agente de Reporte | Consolidación de hallazgos e informe Markdown |
| Skills Controller | Servidor MCP, catálogo de skills, ejecución en contenedores |
| RabbitMQ | Broker de mensajes, colas durables, patrón RPC |
| Frontend (Next.js) | Interfaz gráfica, panel de trazabilidad, visualización de resultados |

*(Diagrama de arquitectura — pendiente de insertar)*

### 10.3 Interacción entre módulos

La interacción sigue un patrón de **RPC sobre colas**: cada agente publica mensajes con `correlation_id` y `reply_to`, y espera la respuesta en una cola temporal. Los flujos principales son: (a) API → Orquestador, (b) Orquestador → Agente de Reconocimiento, (c) Orquestador → Agente de Validación, (d) Orquestador → Agente de Reporte, (e) cualquier agente → Skills Controller para ejecución de skills.

*(Diagrama de interacción entre módulos — pendiente de insertar)*

### 10.4 Comportamiento

Las secuencias principales incluyen: el flujo de reconocimiento (Katana + SPA Crawler → plan de ataque), el flujo de validación (selección de herramienta por vector → ejecución → evidencia), y el flujo de reporte (consolidación → Markdown → publicación). Los puntos críticos de comportamiento incluyen el manejo de timeouts en tres capas (skill, agente, orquestador) y el manejo de errores del modelo con degradación controlada.

*(Diagramas de secuencia — pendientes de insertar)*

---

## 11. Implementación y avance actual

### 11.1 Stack tecnológico

| Categoría | Tecnología |
|-----------|-----------|
| Orquestación de agentes | LangChain + LangGraph |
| Modelo de lenguaje | Qwen 2.5 vía Ollama (local) |
| Comunicación | RabbitMQ + aio-pika |
| Contratos de datos | Pydantic |
| Backend | FastAPI + Python  |
| Frontend | Next.js + React |
| Contenedores | Docker + Docker Compose |
| Herramientas de pentesting | Katana, SPA Crawler, Deep Crawler, SQLMap, DalFox, Commix, Nuclei, FFuF, JWT Tool |

### 11.2 Componentes implementados

- ✅ Infraestructura de mensajería asíncrona (RabbitMQ + RPC)
- ✅ Servidor MCP con catálogo dinámico de 9 skills
- ✅ Ejecución de skills en contenedores Docker efímeros
- ✅ SPA Crawler basado en Playwright con captura de peticiones HTTP
- ✅ Migración del agente de reconocimiento al modelo local (Qwen vía Ollama)
- ✅ API Gateway con endpoint de tareas
- ✅ Persistencia de artefactos y trazabilidad estructurada
- 🔧 Agentes de validación y reporte: migración al modelo local en curso
- 🔧 Validación del flujo completo entre los cuatro agentes: pendiente
- 🔧 Frontend: estructura de componentes lista; integración funcional pendiente

### 11.3 Integraciones realizadas

- Integración MCP entre agentes y skills.
- Integración de RabbitMQ como broker RPC.
- Integración de herramientas de pentesting en contenedores.
- Integración de Ollama como servidor de modelo local.
- Integración de SPA Crawler con el volumen compartido de artefactos.

### 11.4 Pendientes para la entrega final

- Integración completa del frontend con el backend.
- Validación formal del flujo completo sobre Juice Shop.
- Ampliación de la cobertura de skills según resultados de validación.
- Documentación final de la arquitectura y decisiones de diseño.

---

## 12. Despliegue y operación preliminar

El sistema se despliega mediante **Docker Compose**, con servicios definidos para: API Gateway, RabbitMQ, Skills Controller, Orquestador, Agentes (reconocimiento, validación, reporte), entornos vulnerables de validación (Juice Shop), y frontend. El despliegue requiere: Docker Engine, Ollama corriendo con el modelo Qwen, y variables de entorno definidas en `.env`.

---

## 13. Validación preliminar

### 13.1 Pruebas por componentes

Se han validado individualmente: SQLMap (detección de SQLi en Juice Shop sobre `/rest/user/login`), SPA Crawler (descubrimiento de rutas y captura de peticiones), Katana (descubrimiento de endpoints), y la capa de comunicación RabbitMQ.

### 13.2 Pruebas de integración

Durante una fase previa del desarrollo, con el backend de modelos en la nube (Groq), se logró validar el flujo completo API → Orquestador → Reconocimiento → Validación → Reporte sobre Juice Shop, generando informes Markdown con hallazgos y trazabilidad. Tras la migración al modelo local, la integración extremo a extremo se encuentra pendiente: el agente de reconocimiento opera sobre el modelo local, mientras que la migración del agente de validación está en curso. La validación del flujo completo con el modelo local se planifica como actividad de cierre.

### 13.3 Pruebas de usabilidad

Pendiente de validación con usuarios finales (estudiantes) una vez completada la integración frontend.

---

## 14. Resultados parciales y discusión

El proyecto ha consolidado la infraestructura base y ha avanzado en la migración del backend de modelos de lenguaje. Los principales resultados a la fecha incluyen: (a) una arquitectura multiagente con mensajería asíncrona operativa, (b) un servidor MCP con catálogo dinámico de skills ejecutadas en contenedores efímeros, (c) un mecanismo de captura de peticiones SPA (Playwright) que resuelve la limitación de las herramientas tradicionales frente a endpoints POST/JSON, y (d) el agente de reconocimiento funcional sobre el modelo local (Qwen vía Ollama), ejecutando SPA Crawler y Katana y generando un plan de ataque priorizado. La migración del resto de agentes al modelo local está en curso. La transición desde proveedores en la nube hacia un modelo local busca eliminar las cuotas y garantizar la disponibilidad del servicio, a costa de requerir mayor capacidad de cómputo en el host. La validación formal del flujo completo con el modelo local queda como actividad central de la fase de cierre.

---

## 15. Plan de cierre hacia la entrega final

Las actividades restantes se organizan en tres frentes: (1) integración frontend-backend y validación visual, (2) validación del sistema completo sobre Juice Shop con documentación de resultados, y (3) consolidación de la memoria final con diagramas de arquitectura, secuencia y evidencia de validación.

---

## 16. Referencias

1. Anthropic. (2024). *Model Context Protocol specification*. https://modelcontextprotocol.io
2. Brown, T. B., Mann, B., Ryder, N., Subbiah, M., Kaplan, J., Dhariwal, P., ... & Amodei, D. (2020). Language models are few-shot learners. *Advances in Neural Information Processing Systems*, 33, 1877–1901.
3. Cyber Security Intelligence. (2025). *Cyber Security Intelligence: Building sustainable cyber resiliency*. https://cybersecurityinc.net/
4. Deng, G., Liu, Y., Mayoral-Vilches, V., Liu, P., Li, Y., Xu, Y., Zhang, T., Liu, Y., Pinzger, M., & Rass, S. (2023). PentestGPT: An LLM-empowered automatic penetration testing tool. *arXiv preprint arXiv:2308.06782*.
5. Docker. (2025). *Docker documentation*. https://docs.docker.com
6. FIRST. (2019). *Common Vulnerability Scoring System v3.1: Specification document*. Forum of Incident Response and Security Teams. https://www.first.org/cvss/v3.1/specification-document
7. LangChain. (2025). *LangChain documentation*. https://python.langchain.com
8. Microsoft. (2025). *Playwright documentation*. https://playwright.dev
9. Ollama. (2025). *Ollama documentation*. https://ollama.com
10. OWASP Foundation. (2025a). *OWASP Top 10:2025*. https://owasp.org/Top10/2025
11. OWASP Foundation. (2025b). *OWASP Web Security Testing Guide*. https://owasp.org/www-project-web-security-testing-guide
12. OWASP Foundation. (2025c). *OWASP Juice Shop*. https://owasp.org/www-project-juice-shop
13. PortSwigger. (2025). *Katana documentation*. https://github.com/projectdiscovery/katana
14. Pydantic. (2025). *Pydantic documentation*. https://docs.pydantic.dev
15. RabbitMQ. (2025). *RabbitMQ documentation*. https://www.rabbitmq.com
16. Russell, S., & Norvig, P. (2021). *Artificial intelligence: A modern approach* (4th ed.). Pearson.
17. Shannon. (2024). *Shannon: AI pentester for web applications and APIs* [Computer software]. GitHub. https://github.com/KeygraphHQ/shannon
18. SQLMap. (2025). *SQLMap documentation*. https://sqlmap.org
19. Strix. (2025). *Strix: Open-source autonomous AI penetration testing* [Computer software]. GitHub. https://github.com/usestrix/strix
20. Ticarpi. (2025). *jwt_tool: A toolkit for validating, forging, scanning and tampering JWTs* [Computer software]. GitHub. https://github.com/ticarpi/jwt_tool
21. Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A. N., Kaiser, Ł., & Polosukhin, I. (2017). Attention is all you need. *Advances in Neural Information Processing Systems*, 30, 5998–6008.
22. Zhao, W. X., Zhou, K., Li, J., Tang, T., Wang, X., Hou, Y., Min, Y., Zhang, B., Zhang, J., Dong, Z., Du, Y., Yang, C., Chen, Y., Chen, Z., Jiang, J., Ren, R., Li, Y., Tang, X., Liu, Z., ... & Wen, J.-R. (2023). A survey of large language models. *arXiv preprint arXiv:2303.18223*.
23. Fielding, R., & Reschke, J. (2014). *Hypertext Transfer Protocol (HTTP/1.1): Message syntax and routing* (RFC 7230). IETF. https://www.rfc-editor.org/rfc/rfc7230
24. gRPC Authors. (2025). *gRPC documentation*. https://grpc.io/docs/