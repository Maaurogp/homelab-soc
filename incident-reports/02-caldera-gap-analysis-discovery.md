## Gap Analysis — Emulación de Adversario Post-Explotación sobre Domain Controller (MITRE ATT&CK — Discovery)

---

### 1. Resumen Ejecutivo

Se ejecutó una operación de emulación de adversario controlada (`OP-DC-Discover-01`) utilizando **CALDERA** contra el Domain Controller `DC-WinServer` (10.10.20.10), simulando la fase de **reconocimiento post-explotación** que un atacante realiza tras obtener acceso inicial a un controlador de dominio.

El agente ofensivo (Sandcat) fue desplegado bajo un proceso disfrazado como `splunkd.exe` (técnica de _masquerading_, T1036) en `C:\Users\Public\`, ejecutando con privilegios de `CORP\Administrator` (Elevated). Se corrieron 8 técnicas de la matriz MITRE ATT&CK, cubriendo las tácticas de **Discovery** y **Defense Evasion**.

El objetivo del ejercicio fue doble: (1) validar la capacidad de detección de Wazuh + Sysmon ante una amenaza real emulada, y (2) identificar **gaps de visibilidad** entre lo que ocurre en el endpoint y lo que efectivamente genera una alerta correlacionada en el SIEM.

**Hallazgo principal:** Wazuh detectó con éxito y al nivel de severidad máximo la fase de **entrega del payload** (dropping del ejecutable), pero **no generó ninguna alerta** para las 8 técnicas de reconocimiento posteriores, a pesar de que la telemetría de creación de procesos (Sysmon EventID 1) estaba siendo correctamente ingerida por el agente. Esto evidencia un **gap de ingeniería de detección** (reglas de correlación faltantes), no un gap de recolección de datos.

---

### 2. Detalle del Entorno & Telemetría

|Campo|Valor|
|---|---|
|Host Objetivo|`DC-WinServer.corp.local` (Agente Wazuh 005)|
|IP del Host|`10.10.20.10`|
|Usuario del Proceso|`CORP\Administrator`|
|Privilegio|Elevated|
|Proceso del Implante|`splunkd.exe` (masquerading — nombre legítimo de Splunk Forwarder)|
|PID / PPID|6104 / 1764|
|Ubicación del Binario|`C:\Users\Public\splunkd.exe`|
|Herramienta de Emulación|CALDERA (agente Sandcat, C2 sobre HTTP)|
|Ventana Temporal de la Operación|2026-09-04 05:24:09 UTC — 05:30:50 UTC|
|Fuente de Telemetría|Sysmon v15.21 (config SwiftOnSecurity) + Wazuh Agent 4.14.7|

---

### 3. Técnicas Ejecutadas y Resultado de Detección

|#|Comando Ejecutado|Táctica|Técnica MITRE|Resultado en Endpoint|¿Detectado en Wazuh?|
|---|---|---|---|---|---|
|1|`$env:username`|Discovery|Discovery genérico|✅ Éxito|❌ No|
|2|`Get-WmiObject -Class Win32_UserAccount`|Discovery|**T1087** — Account Discovery|✅ Éxito|❌ No|
|3|Enumeración de procesos por owner `Administrator`|Discovery|Discovery genérico|✅ Éxito|❌ No|
|4|`Get-SmbShare \| ConvertTo-Json`|Discovery|**T1135** — Network Share Discovery|✅ Éxito|❌ No|
|5|`nltest /dsgetdc:$env:USERDOMAIN`|Discovery|**T1018** — Remote System Discovery|✅ Éxito|❌ No|
|6|`wmic /NAMESPACE:\\root\SecurityCenter2 ... AntiVirusProduct`|Discovery|**T1518.001** — Security Software Discovery|❌ Falló (namespace inexistente en Windows Server)|N/A|
|7|`gpresult /R`|Discovery|Discovery de GPOs aplicadas|✅ Éxito|❌ No|
|8|Variante WMI de `AntiVirusProduct` vía `root\SecurityCenter`|Discovery|**T1518.001** — Security Software Discovery|❌ Falló (mismo motivo que #6)|N/A|
|—|`Clear-History;Clear`|Defense Evasion|**T1070.003** — Indicator Removal on Host|✅ Ejecutado (output `False`)|❌ No|

**Contraste — fase de entrega del payload (previa a la operación, mismo agente):**

|Evento|Rule ID|Rule Level|Detectado|
|---|---|---|---|
|Ejecutable dropeado en carpeta de uso común de malware (`C:\Users\Public\`)|`92213`|**15** (máximo)|✅ Sí, repetidamente|
|Ejecutable dropeado en `Users\Public`|`92207`|12|✅ Sí|

---

### 4. Análisis de la Causa Raíz (Root Cause del Gap)

La ausencia de alertas para las técnicas de Discovery **no se debe a una falla de recolección de datos**. Sysmon estaba correctamente configurado e ingiriendo eventos de creación de procesos (EventID 1) del agente `DC-WinServer`, y el canal `Microsoft-Windows-Sysmon/Operational` estaba integrado en `ossec.conf` (verificado en fase previa de hardening del agente).

La causa raíz es que el **ruleset de detección de Wazuh (base + SwiftOnSecurity/Sysmon) no contiene reglas de correlación específicas** para los patrones de línea de comandos utilizados (`Get-WmiObject Win32_UserAccount`, `nltest /dsgetdc`, `Get-SmbShare`, `gpresult /R`, `Clear-History`). Los eventos llegaron al índice de Wazuh como datos crudos, pero al no matchear ninguna regla, no se tradujeron en una alerta visible en el dashboard — es decir: **el dato está disponible para threat hunting manual/retroactivo, pero no genera notificación proactiva.**

Esto es consistente con el hallazgo de la fase de entrega: la regla `92213` (nivel 15) que sí disparó **evalúa comportamiento de archivo** (ejecutable nuevo en carpeta de escritura pública), no el nombre del proceso — de hecho, el intento de _masquerading_ como `splunkd.exe` no impidió la detección en absoluto, confirmando que el ruleset de comportamiento de archivos está bien afinado, mientras que el de comportamiento de comandos post-explotación (discovery) presenta un vacío real.

---

### 5. Mapeo MITRE ATT&CK® — Resumen

|Táctica|Técnica|ID|Estado de Detección|
|---|---|---|---|
|Initial Access / Execution|Ingress Tool Transfer|T1105|✅ Detectado (nivel 15)|
|Defense Evasion|Masquerading|T1036|✅ Detectado indirectamente (comportamiento de archivo)|
|Discovery|Account Discovery|T1087|❌ No detectado|
|Discovery|Network Share Discovery|T1135|❌ No detectado|
|Discovery|Remote System Discovery|T1018|❌ No detectado|
|Discovery|Security Software Discovery|T1518.001|⚠️ No aplicable (falló en el endpoint)|
|Defense Evasion|Indicator Removal on Host|T1070.003|❌ No detectado|

---

### 6. Recomendaciones de Remediación (Tuning)

1. **Crear reglas de correlación custom en `local_rules.xml`** para los patrones de comando identificados como no detectados, usando `full_log` con `pcre2` sobre `data.win.eventdata.commandLine` de eventos Sysmon EventID 1 (ejemplos de patrones a cubrir: `Get-WmiObject.*Win32_UserAccount`, `nltest.*dsgetdc`, `Get-SmbShare`, `gpresult`, `Clear-History`).
2. **Asignar nivel de severidad diferenciado por contexto de usuario:** priorizar alertas cuando estos comandos se ejecutan bajo cuentas con privilegio Elevated fuera de horario administrativo habitual, para reducir falsos positivos de uso legítimo por parte de IT.
3. **Evaluar reglas MITRE-mapeadas ya publicadas por la comunidad Wazuh/Sysmon** (ej. proyecto `SwiftOnSecurity` complementado con reglas de detección de LOLBins y PowerShell orientadas a Discovery) en lugar de escribir reglas desde cero.
4. **Repetir el ejercicio tras el tuning** para validar cierre del gap (ciclo de mejora continua: Detect → Tune → Re-test).

---

### 7. Conclusión

Este ejercicio demuestra la diferencia entre **recolección de telemetría** y **detección efectiva**: tener el dato disponible en el SIEM no equivale a tener visibilidad operativa si no existen las reglas de correlación adecuadas. El hallazgo de un gap real de detección en la fase de reconocimiento (Discovery) — inmediatamente después de una detección exitosa y de máxima severidad en la fase de entrega (T1105) — resalta la importancia de auditar el ruleset de forma continua contra el ciclo de vida completo de un ataque (MITRE ATT&CK Kill Chain), no solo su punto de entrada.


---
