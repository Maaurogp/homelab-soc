# Incident Report: Detección de Actividad de Red Sospechosa / Tráfico Inusual (Sysmon EID 3)

## 1. Resumen Ejecutivo
Se registró telemetría de red proveniente del endpoint `DESKTOP-LJV4V4B` (10.10.20.51) interactuando con recursos del Controlador de Dominio `DC-WINSERVER` (10.10.20.10), identificada bajo el mapeo de Movimiento Lateral (SMB/Windows Admin Shares).

## 2. Detalle del Evento y Telemetría
* **Host Afectado:** `DESKTOP-LJV4V4B.corp.local` (Agente 004)
* **IP de Origen:** `10.10.20.51`
* **IP de Destino:** `10.10.20.10` (Puerto 135 / epmap)
* **Imagen del Proceso:** `C:\Users\Public\splunkd.exe`
* **ID de Regla Wazuh:** `92105` (Level 3)
* **Event ID de Windows:** `3` (Network Connection)

## 3. Mapeo con MITRE ATT&CK®
* **Táctica:** Lateral Movement (`TA0008`)
* **Técnica:** SMB/Windows Admin Shares (`T1021.002`)

## 4. Evidencia en Registro de Log (JSON Crudo)
```json
{
  "rule": {
    "id": "92105",
    "level": 3,
    "description": "Possible suspicious access to Windows admin shares"
  },
  "agent": {
    "id": "004",
    "name": "DESKTOP-LJV4V4B",
    "ip": "10.10.20.51"
  },
  "data": {
    "win": {
      "system": {
        "eventID": "3",
        "computer": "DESKTOP-LJV4V4B.corp.local"
      },
      "eventdata": {
        "image": "C:\\Users\\Public\\splunkd.exe",
        "sourceIp": "10.10.20.51",
        "destinationIp": "10.10.20.10",
        "destinationPort": "135"
      }
    }
  }
}
```

---

## 5. Triage

- **Severidad (S):** S1 (Level 3 - Bajo, regla `92105`)
- **Criticidad (C):** C3 (Destino: Domain Controller, VM109)
- **Confianza (F):** F1 (Ejecución manual, sin operación CALDERA que la respalde — única fuente: el evento Sysmon/Wazuh)
- **Prioridad Final:** **P4** (P3 de la matriz, bajado un nivel por F1)
- *Justificación:* a diferencia de los casos 1 y 2, acá no hay un segundo log independiente que confirme intención — el propio gap de que ni CALDERA ni Wazuh dispararon nada automáticamente es parte del hallazgo. Un analista real lo marcaría para revisión, no para descarte directo.

---
