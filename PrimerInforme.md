# Informe del proyecto

## Resumen / Abstract

Este proyecto propone el diseño e implementación de un sistema multiagente inteligente basado en el Protocolo de Contexto de Modelos (MCP) y habilidades (skills) especializadas para automatizar la detección y validación de vulnerabilidades de seguridad en aplicaciones y servicios web. Las herramientas tradicionales de evaluación de vulnerabilidades suelen generar una alta tasa de falsos positivos y no logran determinar si una debilidad es genuinamente explotable. Para superar estas limitaciones, la plataforma propuesta aprovecha agentes autónomos colaboradores que planifican, ejecutan y verifican vectores de ataque en un entorno controlado, reduciendo los falsos positivos y evaluando el riesgo en el mundo real. Los resultados esperados incluyen un prototipo funcional con una biblioteca especializada en ciberseguridad, mecanismos automatizados de planificación de ataques e informes técnicos integrales que incluyen calificaciones de gravedad CVSS y estrategias de mitigación.

## 1. Introducción

En el panorama tecnológico actual, la seguridad de las aplicaciones y servicios expuestos es un pilar crítico para las organizaciones. Las herramientas tradicionales de evaluación de vulnerabilidades, como los escáneres estáticos y dinámicos, suelen limitarse a detectar configuraciones inseguras o debilidades conocidas basándose en firmas estáticas, lo que frecuentemente genera un volumen elevado de falsos positivos y una falta de contexto sobre la explotabilidad real de los hallazgos. El proyecto SECURE aborda esta problemática mediante la integración de inteligencia artificial y arquitecturas de agentes autónomos, diseñando un sistema basado en agentes inteligentes, MCP (Model Context Protocol) y skills especializados que colaboran de forma autónoma para planificar, ejecutar y verificar pruebas de seguridad ofensiva de manera controlada y ética.

### Contextos

- **Dominio o sector** (ej. educación, industria, salud, ciudades inteligentes, TI).
- **Tendencias tecnológicas relevantes**.
- **Rol de los sistemas de información / software / datos** en ese contexto.

### Situación actual

- **Limitaciones del mercado actual**.
- **Carencias funcionales o de diseño**.
- **Impacto en usuarios**.

### Necesidad identificada

- **Necesidad técnica clara**.
- **Oportunidad de diseño tecnológico**.

### Propuesta general

- **Nombre del sistema**.
- **Funcionalidades clave**.
- **Impacto esperado**.

## 2. Planteamiento del problema

¿Cómo automatizar la identificación, validación y reducción de falsos positivos en pruebas de seguridad ofensiva sobre servicios expuestos, superando las limitaciones de los escáneres tradicionales mediante una arquitectura multiagente basada en MCP y skills especializados?

### 2.1 Descripción del problema

Las metodologías convencionales de análisis de vulnerabilidades enfrentan retos significativos:

Falsos positivos masivos: Las herramientas automatizadas tradicionales reportan múltiples alertas que no siempre representan un riesgo real o explotable en el entorno específico de la aplicación.

Falta de razonamiento contextual: Los escáneres carecen de la capacidad analítica para correlacionar diferentes hallazgos, adaptar estrategias de ataque en tiempo real o encadenar vulnerabilidades (vectores de ataque compuestos).

Esfuerzo manual elevado: La validación de la explotabilidad de una vulnerabilidad recae usualmente en profesionales de seguridad (pentesters), lo que consume tiempo y recursos limitados.

SECURE resuelve este problema al introducir agentes inteligentes capaces de razonar sobre los resultados, coordinar estrategias de análisis y confirmar la viabilidad de cada vector mediante pruebas automatizadas y controladas.

### 2.2 Justificación

El desarrollo de esta plataforma se justifica por la necesidad imperativa de optimizar los tiempos y la precisión en las auditorías de ciberseguridad. Al dotar a los sistemas de una arquitectura multiagente que integra herramientas de seguridad existentes mediante MCP, se logra:

Reducir la incertidumbre técnica: Determinar con mayor precisión qué vulnerabilidades son realmente explotables en un entorno autorizado.

Optimizar recursos: Automatizar las fases repetitivas de reconocimiento, enumeración y validación inicial, permitiendo que los expertos humanos se concentren en análisis de mayor complejidad.

Aportar valor académico y práctico: Alinearse con las líneas de Ingeniería de Software, Arquitectura de Software y Seguridad, implementando tecnologías de vanguardia como modelos de agentes y protocolos de contexto estandarizados.

### 2.3 Restricciones y supuestos iniciales

### 2.3.1 Restricciones

- **Ámbito de aplicación:** El prototipo se limitará estrictamente a entornos de laboratorio, aplicaciones web y servicios expuestos en ambientes de pruebas autorizados.
- **Alcance ético y legal:** Queda totalmente excluido el desarrollo de software malicioso (malware), la evasión de mecanismos de seguridad en infraestructuras no autorizadas y la ejecución de pruebas sobre sistemas en producción sin autorización expresa.
- **Dependencia tecnológica:** El rendimiento y la compatibilidad de la plataforma estarán sujetos a la evolución y estabilidad de los modelos de inteligencia artificial y del protocolo MCP utilizados.

### 2.3.2 Supuestos iniciales

1. Se cuenta con acceso a entornos de laboratorio o aplicaciones de prueba debidamente autorizadas para simular los escenarios de ataque de forma controlada.
2. Las herramientas abiertas de análisis y pentesting que se planea integrar mediante MCP mantendrán interfaces compatibles o adaptables para la automatización por parte de los agentes.
3. Los estudiantes participantes poseen conocimientos base en desarrollo de software, arquitectura de sistemas y conceptos fundamentales de seguridad ofensiva para implementar los skills requeridos.

## 3. Alcance del proyecto

El proyecto contempla el desarrollo de un prototipo funcional que permita realizar evaluaciones automatizadas sobre aplicaciones web y servicios expuestos en ambientes de laboratorio o entornos de pruebas autorizados. Nos enfocaremos primeramente en identificar y validar al menos las 4 vulnerabilidades principales del Top de OWASP.

La plataforma incluirá:

1. Arquitectura multiagente basada en MCP.
2. Biblioteca de Skills especializados en tareas de ciberseguridad ofensiva.
3. Integración con herramientas abiertas de análisis y pentesting.
4. Planeación automática de secuencias de ataque mediante colaboración entre agentes.
5. Descubrimiento de vulnerabilidades comunes (ej.  OWASP Top 10).
6. Generación automática de informes técnicos.
7. Registro y trazabilidad de todas las acciones ejecutadas por los agentes.

## 4. Objetivos

### 4.1 Objetivo general

- Diseñar e implementar una arquitectura multiagente basada en MCP y Skills especializados para automatizar la detección de vulnerabilidades en aplicaciones y sistemas mediante pruebas de seguridad ofensiva controladas.

### 4.2 Objetivos específicos

- Diseñar una arquitectura de agentes especializados que colaboren para realizar diferentes etapas de una evaluación de seguridad.
- Implementar Skills/Tools para reconocimiento, enumeración, análisis de configuraciones, identificación de vulnerabilidades y validación de hallazgos.
- Integrar herramientas de seguridad existentes (escáneres, analizadores de código y herramientas de pentesting) mediante MCP para ampliar las capacidades de los agentes.
- Desarrollar mecanismos de coordinación entre agentes para planificar, ejecutar y adaptar estrategias de ataque de forma autónoma.
- Generar reportes técnicos con las vulnerabilidades encontradas, evidencia de explotación, nivel de criticidad y recomendaciones de remediación.
- Evaluar la efectividad de la plataforma usando entornos autorizados para la busqueda de vulnerabilidades.

## 5. Solución propuesta

Describe a alto nivel la solución planteada para abordar el problema identificado. Explica qué se propone construir, quiénes serían sus usuarios, cómo funcionaría de manera general y por qué constituye una respuesta adecuada dentro del alcance definido.

## 6. Estado del arte / soluciones relacionadas

Las herramientas de pen-testing autónomo usando agentes de inteligencia artificial son poderosas para la ciberseguridad actual, sin embargo persisten puntos de mejora como en la legibilidad de las salidas, la transparencia en el razonamiento estratégico, la reducción de falsos positivos y la interactividad de la interfaz.

### 6.1 Soluciones existentes

**Comerciales:**

- CSI
- Strix enterprise

**Open-Source:**

- Strix
- Shannon
- PentestGPT

### 6.2 Oportunidades de mejora

1. **Mejora de experiencia de usuario mediante interfaz gráfica estructurada:** La mayoría de herramientas al ejecutarse en la consola, la interpretación y lectura de los reportes se vuelve tediosa e ineficiente. La incorporación de una interfaz gráfica permite estructurar los informes en paneles más legibles, integrando ayudas visuales que facilitan la compresión rápida de la gravedad de los hallazgos de seguridad.
2. **Visión crítica mediante registro y trazabilidad de los agentes:** Para auditorías de seguridad confiables, no basta con solo conocer el resultado final, es indispensable conocer el procedimiento. Se propone el registro transparente y trazabilidad en tiempo real de cómo cada agente analiza el problema, formula ideas, selecciona Skills/Tools via MCP y resuelve obstáculos. Esto aporta una visión crítica sobre la progresión del ataque.

## 7. Metodología de desarrollo y plan de trabajo

### 7.1 Enfoque metodológico

Para el desarrollo de la aplicación web SECURE, se adopta un enfoque de Prototipado iterativo e incremental. La elección de esta metodología se debe a la arquitectura multiagente y el protocolo MCP, que requieren ciclos continuos de diseño y evaluación.

A continuación se expondrá la dinámica de la metodología:

- **Sprints y Objetivos Semanales:** El desarrollo avanza mediante iteraciones semanales, orientadas a mejorar el prototipo. Cada lunes y/o jueves se establecen objetivos concretos.
- **Reuniones de Tutoría(1 a 2 veces por semana):** Se establecen sesiones periódicas con el docente tutor(fijadas los días lunes y/o jueves) para la presentación de avances, validación del prototipo, oportunidades de mejora y objetivos.
- **Sesiones presenciales de sincronización del equipo(Dia viernes):** Con el objetivo de mantener la dirección del proyecto, tomar decisiones coordinadas y resolver bloqueos de integración, el equipo realiza reuniones presenciales fijas cada viernes.

Especialización de roles y división de responsabilidades: Dada la amplitud técnica de la solución, las responsabilidades se distribuyen entre los 3 integrantes del grupo de la siguiente manera:

1. I**nfraestructura, arquitectura e interfaz visual:** Encargado del diseño de arquitectura del sistema, configuración del entorno, la integración del protocolo MCP y interfaz gráfica principal.
2. **Desarollador de Agentes:** Responsable de los agentes, estrategias de razonamiento, orquestación de agentes y validación de respuestas.
3. **Desarrollador de Skills/Tools:** Especializado en seguridad ofensiva para la creación de skills/tools, además validar el razonamiento de los agentes y proponer puntos de mejora en los ataques.

### 7.2 Iteraciones o fases de desarrollo

El ciclo de vida se organiza en 4 fases principales:

### Fase 1: Análisis, requerimientos y diseño de arquitectura.

**Propósito:** Definir las bases técnicas, la estructura de la aplicación y definición de roles.

**Actividades principales:**

- Levantamiento de requerimientos y priorización de estos
- Diseño arquitectural de la aplicación orientada a protocolo MCP
- Distribución de roles entre integrantes.

### Fase 2: Implementación de infraestructura, Agentes y Skills

**Propósito:** Integrar herramientas (Skills/tools) y  orquestación de agentes

**Actividad principales**:

- Configuración del entorno de infraestructura
- Implementacion de Agentes
- Desarrollo de biblioteca de Skills/Tools via MCP
- Implementación de registro y trazabilidad interna del razonamiento de los agentes

### Fase 3: Integración de la interfaz gráfica y reportes estructurados

**Propósito:** Conectar los agentes con la interfaz visual.

**Actividades principales:**

- Desarrollo de componentes de la interfaz.
- Integración de registro visual del razonamiento agéntico.
- Construcción de reportes estructurados.

### Fase 4: Validación en laboratorio, pruebas y ajustes

**Propósito:** Evaluar la efectividad de la aplicación y refinamiento de ésta.

**Actividades principales:**

- Pruebas sobre entornos controlados autorizados (ej., WebGoat).
- Auditoría de la precisión de los agentes
- Ajustes finales con el fin de un sistema robusto

### 7.3 Estrategia de validación

La evaluación de los avances se logra de la siguiente forma:

1. **Retroalimentación semanal con el tutor:** Durante las reuniones semanales se evalúa el progreso, validando el prototipo y buscando mejoras en él.
2. **Revisión interna presencial:** En las sesiones de grupo el día viernes, se hacen revisiones del código y la lógica detrás para la solución de los diferentes problemas.
3. **Pruebas funcionales en entornos controlados:** Se ejecutan escenarios de prueba en ambientes de laboratorio para comprobar que los agentes encuentren vulnerabilidades reales.
4. **Validación de la interfaz y trazabilidad visual:** Se verifica que la interfaz gráfica exponga de forma legible el razonamiento paso a paso de los agentes y genere informes estructurados significativamente mejores que los escritos en consola.

### 7.4 Plan de trabajo, cronograma e hitos

| Hito / Fase                                | Actividades Principales                                                                                       | Entregables Esperados                                                 | Roles Involucrados                         | Temporalidad Estimada |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------ | --------------------- |
| Hito 1: Fundamentación y Arquitectura     | Levantamiento de requerimientos, diseño de arquitectura MCP y asignación de roles.                          | Documento de arquitectura, diagramas UML y maquetas UI/UX.            | Infraestructura y Agentes                  | Semanas 1 – 4        |
| Hito 2: Core Agéntico, MCP y Trazabilidad | Configuración de infraestructura, implementación de agentes, desarrollo deSkillsy registro de razonamiento. | Motor Multiagente funcional, conectores MCP e infraestructura base.   | Infraestructura y Desarrollador de Agentes | Semanas 5 – 9        |
| Hito 3: Interfaz Gráfica y Visualización | Desarrollo de la interfaz, integración de trazabilidad en tiempo real y generador de reportes visuales.      | Dashboard interactivo integrado y módulo de reportes estructurados.  | Infraestructura y UI                       | Semanas 10 – 13      |
| Hito 4: Pruebas, Ajustes y Entrega Final   | Evaluaciones en laboratorios éticos, validaciones semanales con tutor, optimización y entrega.              | Prototipo v1.0, informe de evaluación de resultados y memoria final. | Todo el equipo                             | Semanas 14 – 16      |

## 8. Referencias

Incluye las fuentes consultadas y citadas en el documento, en el formato de citación definido para el curso o proyecto.
