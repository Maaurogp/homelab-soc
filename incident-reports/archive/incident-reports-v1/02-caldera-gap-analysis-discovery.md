# Incident Report / Threat Emulation Case Study

## Gap Analysis — Emulación de Adversario Post-Explotación sobre Domain Controller (MITRE ATT&CK — Discovery)

---

### 1. Resumen Ejecutivo

Se ejecutó una operación de emulación de adversario controlada (`OP-DC-Discover=01`) utilizando **CALDERA** contra el Domain Controller `DC-WinServer` (10.10.20.10), simulando la fase de **reconocimiento post-explotación** que un atacante realiza tras obtener acceso inicial a un controlador de dominio.

El agente ofensivo (Sandcat) fue desplegado bajo un proceso disfrazado como `splunkd.exe` (técnica de *masquerading*, T1036) en `C:\Users\Public\`, ejecutando con privilegios de `CORP\Administrator`. Se corrieron 8 habilidades de la matriz MITRE ATT&CK bajo la táctica de **Discovery**.

El objetivo del ejercicio fue doble: (1) validar la capacidad de detección de Wazuh + Sysmon ante una amenaza real emulada, y (2) identificar **gaps de visibilidad** entre lo que ocurre en el endpoint y lo que efectivamente genera una alerta correlacionada en el SIEM.

**Hallazgo principal:** Wazuh detectó con éxito y al nivel de severidad máximo la fase de **entrega del payload** (dropping del ejecutable). Para la fase de reconocimiento (Discovery), la detección existe pero presenta un problema de **granularidad**: una única regla genérica (`92031` — "Discovery activity executed", nivel 3, mapeada a T1087) se dispara para múltiples técnicas distintas ejecutadas (enumeración de usuarios, shares administrativos, ubicación del DC, grupos de permisos), sin diferenciar cuál ocurrió realmente. Adicionalmente, se identificó una **segunda inconsistencia de mapeo MITRE** (sumada a la ya documentada en el caso de fuerza bruta): una alerta de "archivo dropeado" fue clasificada por Wazuh bajo la táctica *Lateral Movement* (T1570), cuando el comportamiento real corresponde a *Command and Control / Ingress Tool Transfer* (T1105), igual que otras alertas del mismo tipo de evento.

---

### 2. Detalle del Entorno & Telemetría

| Campo | Valor |
|---|---|
| Host Objetivo | `DC-WinServer` (Agente Wazuh 005) |
| IP del Host | `10.10.20.10` |
| Usuario del Proceso | `CORP\Administrator` |
| Proceso del Implante | `splunkd.exe` (masquerading — nombre legítimo de Splunk Forwarder) |
| Ubicación del Binario | `C:\Users\Public\splunkd.exe` |
| Herramienta de Emulación | CALDERA v5.3.0 (agente Sandcat, C2 sobre HTTP) |
| Nombre de la Operación | `OP-DC-Discover=01` (8 decisiones) |
| Fuente de Telemetría | Sysmon v15.21 (config SwiftOnSecurity) + Wazuh Agent 4.14.7 |

---

### 3. Evidencia — Ejecución de la Operación (CALDERA)

![Operación CALDERA - técnicas de Discovery](../media/02-caldera-operation-discovery-links.png)

La operación ejecutó 8 habilidades bajo la táctica *Discovery*, con el siguiente resultado:

| # | Ability Name | Estado | Técnica MITRE probable |
|---|---|---|---|
| 1 | Identify active user | ✅ success | Discovery genérico |
| 2 | Identify local users | ✅ success | **T1087** — Account Discovery |
| 3 | Find user processes | ✅ success | Discovery genérico |
| 4 | View admin shares | ✅ success | **T1135** — Network Share Discovery |
| 5 | Discover domain controller | ✅ success | **T1018** — Remote System Discovery |
| 6 | Discover antivirus programs | ❌ failed | T1518.001 — Security Software Discovery |
| 7 | Permission Groups Discovery | ✅ success | **T1069** — Permission Groups Discovery |
| 8 | Identify Firewalls | ❌ failed | T1518.001 — Security Software Discovery |

Las 2 fallas (#6 y #8) son consistentes con un ejercicio anterior sobre el mismo host: ambas dependen del namespace WMI `root\SecurityCenter2`, que **no existe en Windows Server** (es exclusivo de ediciones Desktop/Client). No es una falla del agente ni del ejercicio, es una limitación esperada del sistema operativo objetivo.

---

### 4. Evidencia — Detección Fuerte (Entrega del Payload)

![Detección regla 92213 - nivel 15](../media/02-wazuh-deteccion-92213-nivel15.png)

Wazuh detectó el dropping del binario `splunkd.exe` en `C:\Users\Public\` mediante la regla **92213** ("Executable file dropped in folder commonly used by malware"), con **nivel de severidad 15 (el máximo posible)**, mapeada correctamente a **T1105 (Ingress Tool Transfer, táctica Command and Control)**.

Esto confirma que el intento de *masquerading* (nombrar el binario como `splunkd.exe`, un proceso legítimo de Splunk) **no impidió la detección**: la regla evalúa comportamiento de archivo (ejecutable nuevo en ubicación de escritura pública), no el nombre del proceso.

---

### 5. Evidencia — Segunda Inconsistencia de Mapeo MITRE

![Inconsistencia mapeo T1570](../media/02-wazuh-mitre-inconsistencia-t1570.png)

Se identificó la regla **92217** ("Executable dropped in Windows..."), nivel 6, mapeada por Wazuh a **T1570 (Lateral Movement)**. Este es el mismo tipo de evento que la regla 92213 (archivo ejecutable dropeado en una ubicación sospechosa), pero mapeado a una táctica distinta e incorrecta: dropear un archivo en el propio host comprometido no constituye movimiento lateral (que implica desplazamiento hacia *otro* sistema dentro de la red).

Este hallazgo se suma al identificado en el caso de uso de fuerza bruta (donde la regla 60122 fue mapeada incorrectamente a T1531), reforzando una conclusión metodológica: **el mapeo automático de MITRE ATT&CK en el ruleset de Wazuh no siempre es preciso, y debe ser validado por el analista contra la definición oficial de la técnica antes de tomarlo como base para el triage o el reporte.**

---

### 6. Evidencia — Gap de Granularidad en Técnicas de Discovery

![Gap de granularidad - regla genérica 92031](../media/02-wazuh-gap-discovery-t1087.png)

Al filtrar por `agent.name:"DC-WinServer" AND (rule.mitre.id:"T1087" OR rule.mitre.id:"T1135" OR rule.mitre.id:"T1018" OR rule.mitre.id:"T1069")`, se obtuvieron **28 resultados** (114 en total al buscar directamente por `rule.id:"92031"`, incluyendo eventos de otros agentes y de días previos a esta operación).

**Todos los resultados corresponden a la misma regla:** `92031` — "Discovery activity executed", nivel 3, mapeada uniformemente a **T1087**. Esto ocurre independientemente de cuál de las 4 técnicas de Discovery ejecutadas (`Identify local users`, `View admin shares`, `Discover domain controller`, `Permission Groups Discovery`) haya sido la que disparó la alerta.

**Conclusión de este hallazgo:** no se trata de una ausencia total de detección (como se hipotetizó inicialmente), sino de un **problema de granularidad**: el ruleset agrupa múltiples técnicas de reconocimiento distintas (T1087, T1135, T1018, T1069) bajo una única regla genérica y de baja severidad. Esto tiene una consecuencia operativa concreta para un analista: al ver una alerta de nivel 3 "Discovery activity executed", no hay forma de distinguir desde el dashboard si el atacante enumeró usuarios, shares de red, o grupos de permisos — información crítica para dimensionar el alcance real de un incidente durante el triage.

---

### 7. Mapeo MITRE ATT&CK® — Resumen

| Táctica | Técnica | ID | Estado de Detección |
|---|---|---|---|
| Command and Control | Ingress Tool Transfer | T1105 | ✅ Detectado (nivel 15, correctamente mapeado) |
| Defense Evasion | Masquerading | T1036 | ✅ Detectado indirectamente (comportamiento de archivo) |
| — (mapeo incorrecto de Wazuh) | "Lateral Movement" | T1570 | ⚠️ Mapeo impreciso — mismo evento que T1105 |
| Discovery | Account Discovery | T1087 | ⚠️ Detectado, pero sin diferenciación (regla genérica 92031) |
| Discovery | Network Share Discovery | T1135 | ⚠️ Detectado bajo la misma regla genérica (mapeado igual que T1087) |
| Discovery | Remote System Discovery | T1018 | ⚠️ Detectado bajo la misma regla genérica (mapeado igual que T1087) |
| Discovery | Permission Groups Discovery | T1069 | ⚠️ Detectado bajo la misma regla genérica (mapeado igual que T1087) |
| Discovery | Security Software Discovery | T1518.001 | ⚠️ No aplicable (falló en el endpoint por incompatibilidad de SO) |

---

### 8. Análisis de la Causa Raíz

La detección de las técnicas de Discovery no falla por falta de recolección de datos — Sysmon capturó correctamente los eventos de creación de proceso (EventID 1) del host, y el canal `Microsoft-Windows-Sysmon/Operational` está integrado en la configuración del agente. La regla `92031` sí existe y sí se dispara.

La causa raíz del problema es de **diseño de reglas, no de recolección**: el ruleset actual implementa una única regla genérica ("Discovery activity executed") que actúa como catch-all para múltiples patrones de comandos de reconocimiento distintos, todos mapeados de forma idéntica a T1087 y con severidad fija en nivel 3. Esto simplifica la implementación de la regla pero sacrifica la capacidad de un analista de diferenciar, desde la alerta misma, qué tipo específico de reconocimiento ocurrió — información necesaria para priorizar la respuesta (por ejemplo, la enumeración de shares administrativos o de grupos de permisos en un DC debería considerarse de mayor riesgo que simplemente identificar el usuario activo).

Sumado al hallazgo de la Sección 5 (mapeo incorrecto de T1570 en la regla 92217), se concluye que el ruleset actual está bien afinado para **detección de comportamiento de archivos** (T1105/T1036) con alta severidad y precisión, pero presenta debilidades tanto en la **granularidad de detección de comandos de reconocimiento** (Discovery) como en la **precisión del mapeo táctico** de algunas reglas ya existentes.

---

### 9. Recomendaciones de Remediación (Tuning)

1. **Desagregar la regla `92031`** en reglas hijas específicas por patrón de comando (`local_rules.xml`), usando `pcre2` sobre `data.win.eventdata.commandLine` de eventos Sysmon EventID 1, para diferenciar T1087, T1135, T1018 y T1069 con IDs y niveles de severidad propios.
2. **Escalar la severidad de reglas de Discovery ejecutadas contra un Domain Controller** — el contexto del host (DC vs. endpoint estándar) debería influir en el nivel asignado; nivel 3 subestima el riesgo real de reconocimiento activo sobre un activo crítico.
3. **Corregir el mapeo MITRE de la regla 92217** de T1570 (Lateral Movement) a T1105 (Ingress Tool Transfer), consistente con la regla 92213 que cubre el mismo comportamiento.
4. **Auditar el ruleset completo por mapeos MITRE inconsistentes** — este es el segundo caso encontrado (el primero fue la regla 60122 → T1531 en el caso de fuerza bruta), lo cual sugiere que puede haber más reglas con el mismo problema.
5. **Repetir el ejercicio tras el tuning** para validar el cierre de ambos hallazgos (ciclo de mejora continua: Detect → Tune → Re-test).

---

### 10. Conclusión

Este ejercicio refuerza y matiza el hallazgo del ejercicio anterior: tener telemetría disponible en el SIEM y una regla que se dispare no equivale automáticamente a tener visibilidad operativa completa. Se identificaron dos tipos de debilidad distintos — falta de granularidad en la detección de Discovery (múltiples técnicas colapsadas en una sola regla genérica de baja severidad) e imprecisión en el mapeo MITRE de reglas existentes (T1570 vs T1105) — ambos accionables mediante tuning del ruleset, sin requerir reescribir la arquitectura de detección desde cero. La recurrencia del segundo tipo de hallazgo en dos casos de uso distintos sugiere que la validación manual del mapeo MITRE debería ser un paso estándar del proceso de triage, no una excepción puntual.
