## Incident Report Simulación de Fuerza Bruta - Credenciales Inválidas sobre SMB (MITRE T1110)

1. **Resumen Ejecutivo:** Se detectó una ráfaga de intentos fallidos de inicio de sesión de red desde la estación de trabajo `DESKTOP-LJV4V4B` (10.10.20.51) haciendo uso de un usuario no registrado en el dominio (`CORP\FalsoUsuario`). La actividad fue capturada por el canal de Auditoría de Seguridad de Windows y procesada por el SIEM Wazuh.

2. **Detalle del Evento & Telemetría**
	- *Host Afectado:* `DESKTOP-LJV4V4B.corp.local` (Agente 004)
	- *IP de Origen:* `127.0.0.1` (Local Loopback)
	- *Usuario Objetivo:* `CORP\FalsoUsuario`
	- *Tipo de Logon (Logon Type):* 3 (Network Logon)
	- *ID de Regla Wazuh:* `60122` (Level 5)
	- *Event ID de Windows*: `4625` (Audit Failure)

3. **Mapeo con MITRE ATT&CK®**
	- *Táctica:* Credential Access (`TA0006`)
	- *Técnica:* Brute Force: Password Guessing (`T1110.001`)

4. **Evidencia en Registro de Log (JSON Crudo):**
```json
{
  "rule": {
    "id": "60122",
    "level": 5,
    "description": "Logon Failure - Unknown user or bad password"
  },
  "agent": {
    "id": "004",
    "name": "DESKTOP-LJV4V4B",
    "ip": "10.10.20.51"
  },
  "data": {
    "win": {
      "system": {
        "eventID": "4625",
        "channel": "Security",
        "computer": "DESKTOP-LJV4V4B.corp.local"
      },
      "eventdata": {
        "targetUserName": "FalsoUsuario",
        "targetDomainName": "CORP",
        "logonType": "3",
        "status": "0xc000006d",
        "subStatus": "0xc0000064",
        "ipAddress": "127.0.0.1"
      }
    }
  }
}
```
