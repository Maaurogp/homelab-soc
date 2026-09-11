# Incident Report: Reconocimiento Local y Descubrimiento en Host Windows 10 (MITRE TA0007 / TA0002)

## 1. Resumen Ejecutivo
Durante una simulación de emulación de amenazas coordinada desde el servidor CALDERA (`10.10.1.54`), se ejecutaron múltiples comandos de reconocimiento local (*Discovery*) sobre el host miembro del dominio `DESKTOP-LJV4V4B` (`10.10.20.51`). La actividad consistió en la enumeración de usuarios activos, grupos del dominio, procesos en ejecución, recursos compartidos, servicios de firewall y componentes antivirus. 

El análisis de brechas (*Gap Analysis*) en el SIEM Wazuh reveló que comandos de consola individuales (`whoami`, `net user`, `tasklist`) no generaban alertas de alta severidad por defecto. En consecuencia, se desarrolló e implementó la regla personalizada `100012` para garantizar cobertura analítica ante técnicas de reconocimiento en CLI.

---

## 2. Detalle del Evento & Telemetría del Endpoint
* **Host Afectado:** `DESKTOP-LJV4V4B` (VM 108 - Agente Wazuh `004`)
* **IP del Host:** `10.10.20.51` (VLAN 20)
* **Origen de la Orquestación:** CALDERA C2 Server (`10.10.1.54` - VLAN 1)
* **Vector de Ejecución:** Agente Sandcat corriendo en el proceso cliente.
* **Canal de Auditoría:** `Microsoft-Windows-Sysmon/Operational` (Event ID 1 - Process Creation)

---

## 3. Mapeo con MITRE ATT&CK®

| Fase / Ability | Táctica ATT&CK | Técnica ATT&CK | Comando Ejecutado en Endpoint |
| :--- | :--- | :--- | :--- |
| **Identify active user** | Discovery (`TA0007`) | System Owner/User Discovery (`T1033`) | `whoami` |
| **Identify local users** | Discovery (`TA0007`) | Account Discovery: Local Account (`T1087.001`) | `net user` |
| **Find user processes** | Discovery (`TA0007`) | Process Discovery (`T1057`) | `tasklist` |
| **View admin shares** | Discovery (`TA0007`) | Network Share Discovery (`T1135`) | `net share` |
| **Discover domain controller** | Discovery (`TA0007`) | Remote System Discovery (`T1018`) | `nltest /dsgetdc:` |
| **Discover antivirus programs** | Discovery (`TA0007`) | Software Discovery (`T1518`) | `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct` |
| **Permission Groups Discovery** | Discovery (`TA0007`) | Account Discovery: Domain Groups (`T1087.002`) | `net group "Domain Admins" /domain` |
| **Identify Firewalls** | Discovery (`TA0007`) | System Information Discovery (`T1082`) | `netsh advfirewall show allprofiles` |

---

## 4. Análisis de Gaps & Regla de Detección Creada

### Gap Identificado
Los binarios nativos del sistema (*LOLBins*) utilizados para reconocimiento suelen ser pasados por alto por reglas estándar del SIEM al no ser intrínsecamente maliciosos. Wazuh clasificaba la mayoría de estos eventos bajo reglas genéricas de baja prioridad (Nivel 4 / Rule ID `92052`).

### Regla Personalizada Creada (`/var/ossec/etc/rules/local_rules.xml`)
Se definió la regla `100012` para elevar a **Nivel 8** las alertas cuando se detecte la invocación CLI de patrones de reconocimiento conocidos:

```xml

### Evidencia de Ejecución (CALDERA)
![Descubrimiento CALDERA](../media/Descubrimiento%20por%20caldera.png)

### Telemetría Recolectada (Wazuh)
![Descubrimiento Wazuh](../media/Descubrimiento%20Wazuh.png)


<!-- Regla Custom 100012: Detección de Comandos de Discovery en CLI (VM108 Gap Fix) -->
<rule id="100012" level="8">
  <if_sid>61600</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\b(whoami|net\s+user|net\s+localgroup|tasklist|nltest|netsh\s+advfirewall)\b</field>
  <description>SOC-LAB: Reconocimiento Local / Discovery detectado en CLI ($(win.eventdata.image))</description>
  <mitre>
    <id>T1082</id>
    <id>T1087.001</id>
  </mitre>
</rule>
