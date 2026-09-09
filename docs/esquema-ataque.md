# Esquema de Ataque y Modelado de Amenazas

## 1. Narrativa del Escenario
El objetivo de este escenario es simular una cadena de ataque dirigida en un entorno corporativo simulado. Un atacante compromete inicialmente una estación de trabajo miembro del dominio (VM 108), realiza reconocimiento local y extracción de información, obtiene credenciales de acceso y ejecuta un movimiento lateral hacia el Controlador de Dominio (VM 109) para consolidar el control de la infraestructura de Active Directory.

---

## 2. Matriz de Mapeo: Técnica, Táctica, VM y Ability de CALDERA

| Fase | VM Objetivo | Táctica ATT&CK | Técnica ATT&CK | Ability / Herramienta CALDERA |
| :--- | :--- | :--- | :--- | :--- |
| **A** | VM 108 | Execution | T1059 (Command and Scripting Interpreter: PowerShell) | `PowerShell execution` / Sandcat Agent |
| **B** | VM 108 | Discovery | T1082 (System Information Discovery) | `System Discovery` (Query OS/Architecture) |
| **C** | VM 108 | Credential Access | T1552 (Unsecured Credentials) o T1003 (OS Credential Dumping) | `Dump Credential Artifacts` / Local Sam Dump |
| **D** | VM 108 → 109 | Lateral Movement | T1021 (Remote Services: SMB/WinRM) | `Remote Execution via WinRM / SMB` |
| **E** | VM 109 | Credential Access | T1003.001 (OS Credential Dumping: LSASS Memory) | `Dump LSASS memory (Mimikatz)` |
| **F** | VM 109 | Persistence | T1053.005 (Scheduled Task/Job: Scheduled Task) | `Create Scheduled Task for Persistence` |

---

## 3. Metodología de Detección y Validación
Cada una de las fases anteriores se audita mediante:
1. **Telemetría de Endpoint:** Recolección mediante Sysmon (Event ID 1 para ejecución de procesos, Event ID 10 para acceso a procesos como LSASS, Event ID 4624/4648 para autenticación).
2. **Ingesta SIEM:** Wazuh Manager (VM 104) procesando los logs a través de reglas predeterminadas y reglas locales custom (`local_rules.xml`).
3. **Análisis de Brechas (Gap Analysis):** Identificación de la efectividad de las reglas actuales frente a las técnicas ejecutadas por CALDERA.
