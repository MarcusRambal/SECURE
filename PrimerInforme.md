# Informe del proyecto

## Resumen / Abstract

Este proyecto propone el diseño e implementación de un sistema multiagente inteligente basado en el Protocolo de Contexto de Modelos (MCP) y habilidades (skills) especializadas para automatizar la detección y validación de vulnerabilidades de seguridad en aplicaciones y servicios web. Las herramientas tradicionales de evaluación de vulnerabilidades suelen generar una alta tasa de falsos positivos y no logran determinar si una debilidad es genuinamente explotable. Para superar estas limitaciones, la plataforma propuesta aprovecha agentes autónomos colaboradores que planifican, ejecutan y verifican vectores de ataque en un entorno controlado, reduciendo los falsos positivos y evaluando el riesgo en el mundo real. Los resultados esperados incluyen un prototipo funcional con una biblioteca especializada en ciberseguridad, mecanismos automatizados de planificación de ataques e informes técnicos integrales que incluyen calificaciones de gravedad CVSS y estrategias de mitigación.

## 1. Introducción

En el panorama tecnológico actual, la evaluación periódica de la seguridad en aplicaciones y servicios expuestos constituye un componente importante dentro del ciclo de vida del software. En la práctica, los equipos de desarrollo y ciberseguridad utilizan diferentes herramientas de análisis para identificar posibles debilidades en sus sistemas. Sin embargo, algunos flujos de análisis pueden generar grandes cantidades de información técnica que requieren una interpretación manual considerable, especialmente cuando los resultados provienen de diferentes herramientas o componentes y deben ser relacionados para comprender su contexto.

Para abordar esta oportunidad de mejora, el proyecto SECURE propone una plataforma asistida basada en una arquitectura multiagente e integrada mediante el Protocolo de Contexto de Modelos (Model Context Protocol, MCP) y skills especializados de ciberseguridad. En lugar de centrarse únicamente en la generación de resultados técnicos, SECURE busca mejorar la experiencia de usuario (UX) mediante un panel gráfico que permita visualizar de forma estructurada el flujo de análisis, incluyendo las acciones, decisiones y resultados relevantes de los agentes. De esta manera, se busca facilitar la comprensión, organización, correlación y filtrado inicial de hallazgos obtenidos en entornos de prueba autorizados.

### Contextos

- **Dominio o sector:** Tecnologías de la Información (TI), desarrollo de software y evaluación de ciberseguridad.
- **Tendencias tecnológicas relevantes:** Modelos de Lenguaje (LLM) aplicados a tareas de análisis de software, arquitecturas multiagente, el estándar Model Context Protocol (MCP) para la integración modular de herramientas y marcos de referencia de vulnerabilidades web, como OWASP Top 10.
- **Rol de los sistemas de información / software / datos:** Actúan como objeto de prueba y evaluación. La plataforma propuesta funcionará como una herramienta de soporte encargada de organizar, procesar y presentar visualmente los datos obtenidos durante el análisis para facilitar su interpretación por parte de los evaluadores humanos.

### Situación actual

- **Limitaciones identificadas:** Algunos flujos y herramientas de análisis de seguridad presentan resultados técnicos en formatos que pueden requerir una interpretación manual considerable, especialmente cuando existe una gran cantidad de información o cuando los resultados proceden de diferentes fuentes.
- **Oportunidad de diseño:** Existe la posibilidad de mejorar la forma en que los resultados de diferentes componentes de análisis son organizados, relacionados y presentados al usuario, especialmente mediante una interfaz que permita visualizar el flujo seguido durante una evaluación.
- **Impacto en usuarios:** La revisión de grandes cantidades de información técnica puede dificultar la identificación de los resultados más relevantes y aumentar el esfuerzo necesario para comprender el contexto de cada hallazgo.

### Necesidad identificada

- **Necesidad técnica clara** Disponer de mecanismos de interacción y visualización que mejoren la legibilidad y estructuración de los resultados de seguridad, acompañados de un registro comprensible del flujo de análisis realizado por los diferentes agentes.
- **Oportunidad de diseño tecnológico** Aprovechar el protocolo MCP para facilitar la integración entre los agentes y las herramientas de análisis, complementándolo con una interfaz web que presente de manera ordenada las acciones, decisiones y resultados relevantes producidos durante el proceso.

### Propuesta general

- **Nombre del sistema: SECURE** (System for Ethical Cybersecurity and Automated Reasoning Environment).
- **Funcionalidades clave**
    1. Arquitectura multiagente apoyada en MCP para coordinar tareas de análisis dentro de un flujo previamente definido, incluyendo reconocimiento, enumeración y análisis de configuraciones.
    2. Conjunto de skills orientados al análisis de un grupo seleccionado de vulnerabilidades web, tomando como referencia categorías del OWASP Top 10.
    3. Panel de control gráfico (Dashboard) con un registro estructurado y visual del flujo de análisis, incluyendo las acciones y resultados relevantes de los agentes.
    4. Generación de informes técnicos organizados, acompañados de una clasificación preliminar de severidad y posibles recomendaciones de mitigación.
- **Impacto esperado** Facilitar la comprensión y organización de los resultados obtenidos durante una evaluación de seguridad, proporcionando al usuario una representación más estructurada del proceso de análisis y de los hallazgos identificados.

## 2. Planteamiento del problema

### Formulación del Problema

¿Cómo mejorar la legibilidad, la transparencia analítica y la experiencia de usuario en la evaluación asistida de vulnerabilidades web, mediante una arquitectura multiagente basada en MCP, skills especializados y una interfaz estructurada para visualizar el flujo de análisis y sus resultados?

### 2.1 Descripción del problema

En los flujos de auditoría y análisis de seguridad en software, la experiencia operativa puede presentar dificultades relacionadas con la organización, interpretación y correlación de la información obtenida:

1. **Complejidad en la interpretación de resultados:** Algunos procesos de análisis pueden generar grandes cantidades de información técnica, lo que dificulta identificar rápidamente los resultados relevantes y comprender su contexto cuando estos se presentan de manera poco estructurada.
2. **Limitada visibilidad del flujo de análisis:** Cuando intervienen diferentes herramientas o componentes automatizados, puede resultar difícil para el usuario identificar qué acciones se realizaron, qué información fue utilizada y cómo se relacionan los diferentes resultados obtenidos durante el proceso.
3. **Presencia de alertas imprecisas:** Las herramientas automatizadas pueden generar alertas que requieren una revisión posterior para determinar su relevancia dentro del contexto específico del entorno evaluado. La organización y correlación de la información puede contribuir a una priorización inicial de estos hallazgos.

SECURE aborda este problema mediante la propuesta de un entorno visual que permita organizar y representar de forma estructurada el flujo de análisis, facilitando al usuario la interpretación de los resultados y la identificación de los hallazgos que requieren mayor atención.

### 2.2 Justificación

El desarrollo de esta plataforma se justifica en los siguientes aspectos:

- **Experiencia de Usuario (Usabilidad):** Un dashboard interactivo puede facilitar la visualización y organización de los resultados de una evaluación de seguridad, permitiendo consultar información como el origen, contexto y severidad preliminar de cada observación sin depender exclusivamente de salidas técnicas poco estructuradas.
- **Transparencia y Trazabilidad:** El registro estructurado de las acciones, decisiones y resultados relevantes de cada agente permite representar de forma comprensible el flujo seguido durante el análisis. Esto proporciona mayor contexto para interpretar cómo se obtuvo cada hallazgo, sin depender de la visualización del razonamiento interno del modelo de lenguaje.
- **Aportación Técnica y Académica:** El proyecto permitirá explorar de forma práctica el uso del estándar MCP dentro de una arquitectura de software, integrando conceptos relacionados con ciberseguridad, diseño de interfaces, procesamiento de información y sistemas multiagente.

### 2.3 Restricciones y supuestos iniciales

### 2.3.1 Restricciones

- **Entorno de aplicación:** El prototipo operará de forma acotada sobre aplicaciones web y servicios disponibles en entornos de laboratorio o de prueba debidamente autorizados, como entornos educativos diseñados para prácticas de seguridad.
- **Marco ético:** Queda excluido el desarrollo de código malicioso, el intento de evasión de mecanismos de defensa en entornos no autorizados o la ejecución de pruebas sobre infraestructura de producción sin el permiso correspondiente.
- **Alcance de análisis:** La biblioteca de skills se limitará a un conjunto reducido y representativo de vulnerabilidades web seleccionadas, tomando como referencia categorías del OWASP Top 10. El proyecto no pretende cubrir de manera exhaustiva todas las categorías de dicho marco.
- **Alcance de automatización:** La plataforma se enfocará en asistir y organizar el proceso de análisis, sin plantear inicialmente la explotación autónoma de vulnerabilidades ni la ejecución de pruebas ofensivas complejas.
- **Desempeño del modelo:** Los resultados generados con apoyo de modelos de lenguaje estarán condicionados por las capacidades, limitaciones y configuración del modelo utilizado. Por esta razón, los resultados deberán considerarse como apoyo al análisis y no como sustituto de la validación humana.

### 2.3.2 Supuestos iniciales

1. Se tendrá acceso a entornos de laboratorio controlados para realizar las validaciones del sistema.
2. Las herramientas seleccionadas para la integración mediante MCP proporcionarán resultados que puedan ser procesados y estructurados por la plataforma.
3. El equipo de desarrollo cuenta con las bases técnicas necesarias para diseñar la arquitectura web, desarrollar la interfaz gráfica y realizar una implementación inicial de los componentes multiagente y de integración.
4. El alcance funcional de la plataforma podrá ajustarse durante el desarrollo de acuerdo con los resultados obtenidos, las limitaciones técnicas identificadas y el tiempo disponible para el proyecto.

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

La solución planteada consiste en el desarrollo de SECURE, un sistema web de evaluación asistida de seguridad que combina una arquitectura multiagente, el estándar MCP (Model Context Protocol) y una interfaz gráfica para la visualización estructurada del flujo de análisis y sus resultados.

### ¿Qué se propone construir?

Se propone desarrollar una plataforma web compuesta por tres componentes principales:

1. **Módulo Multiagente (Backend):** Conjunto de agentes coordinados mediante roles definidos, por ejemplo, un Agente Reconocedor, un Agente Analista y un Agente Reportador. Estos componentes estarán orientados a procesar la información obtenida durante el análisis y ejecutar las tareas correspondientes dentro del flujo definido para la evaluación.
2. **Capa de Integración MCP y Skills:** Conjunto de skills modulares conectados mediante MCP que permitirán a los agentes interactuar con herramientas seleccionadas de análisis de seguridad de una manera estructurada.
3. **Interfaz Gráfica y Panel de Trazabilidad (Frontend):** Panel web encargado de presentar la información procesada por los agentes en un formato limpio y estructurado. La interfaz permitirá visualizar el progreso de la evaluación, las acciones relevantes realizadas y los resultados asociados a cada etapa del análisis.

### ¿Quiénes serán sus usuarios?

- **Estudiantes y aprendices de Ciberseguridad/DevOps:** Podrán utilizar la plataforma como apoyo para comprender el flujo general de una evaluación de seguridad y consultar sus resultados mediante una interfaz visual.
- **Desarrolladores de Software:** Podrán utilizarla para analizar aplicaciones disponibles en entornos de laboratorio o prueba autorizados y consultar los resultados obtenidos junto con posibles recomendaciones de mitigación.
- **Evaluadores o tutores:** Podrán utilizar la información estructurada del sistema para revisar el flujo de análisis y los resultados generados durante las pruebas realizadas.

### ¿Cómo funcionará de manera general?

1. **Configuración:** El usuario proporcionará la dirección de una aplicación objetivo disponible en un entorno de pruebas autorizado y seleccionará las opciones de análisis disponibles.
2. **Análisis e interacción entre agentes:** Los agentes ejecutarán las tareas correspondientes dentro del flujo de análisis y podrán consultar las skills disponibles mediante MCP. La plataforma registrará información relevante del proceso, como las herramientas consultadas, las acciones realizadas y los resultados obtenidos.
3. **Procesamiento de resultados:** El sistema organizará la información recopilada y aplicará reglas de validación inicial para identificar y priorizar posibles hallazgos inconsistentes. Posteriormente, los resultados serán organizados y asociados con una clasificación preliminar de severidad.
4. **Visualización y reporte:** En el dashboard web, el usuario podrá consultar el historial estructurado de la evaluación, revisar los hallazgos identificados y, de acuerdo con las funcionalidades implementadas, generar un informe técnico con su información relevante y posibles recomendaciones de mitigación.

### ¿Por qué constituye una respuesta adecuada?

Esta propuesta constituye una respuesta adecuada al problema planteado debido a que concentra el desarrollo en aspectos que pueden abordarse de manera progresiva dentro del alcance del proyecto: la organización de los resultados, la integración de herramientas mediante MCP, la coordinación de componentes especializados y la presentación visual de la información obtenida durante el análisis.

La propuesta no busca reemplazar al evaluador humano ni realizar de manera autónoma un proceso completo de auditoría o explotación de vulnerabilidades. En cambio, SECURE se plantea como una herramienta de asistencia que busca facilitar la consulta, organización y comprensión de los resultados obtenidos en entornos de prueba autorizados.

El alcance podrá evolucionar durante las siguientes etapas del proyecto de acuerdo con los avances de implementación y las validaciones realizadas. De esta manera, las funcionalidades inicialmente propuestas podrán ser ampliadas o ajustadas con base en los resultados obtenidos durante el desarrollo.

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
