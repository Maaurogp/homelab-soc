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
