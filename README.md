# Homelab SOC — Detección y Threat Hunting en Active Directory

Homelab de ciberseguridad orientado a Blue Team, construido en Proxmox VE con
segmentación de red por VLANs (pfSense), un SIEM (Wazuh + Sysmon) y ejercicios
de emulación de adversario (CALDERA) contra un Active Directory real on-premise.

El proyecto está diseñado para ser escalable: hoy cubre detección y triage
básico orientado a un rol de SOC Analyst N1, con una arquitectura pensada
para crecer en profundidad (case management, threat intelligence, más
escenarios de emulación) a medida que avanzo en mi carrera.

## Qué incluye

- Arquitectura segmentada en 4 VLANs (SOC Core, DMZ/Targets, Active Directory,
  Microservicios/Web) enrutadas mediante pfSense.
- SIEM Wazuh con agentes desplegados en Linux, Windows Server (Domain
  Controller) y Windows Client, con telemetría enriquecida por Sysmon.
- Targets vulnerables (Metasploitable2, DVWA, WebGoat, bWAPP) para práctica
  ofensiva/defensiva.
- Emulación de adversario con CALDERA (MITRE ATT&CK) contra el Domain
  Controller, con análisis de gap de detección documentado.

## Casos de uso documentados

1. **[Fuerza bruta sobre SMB (T1110)](incident-reports/01-fuerza-bruta-smb-t1110.md)**
   — Detección de intentos de autenticación fallida, incluyendo la
   identificación de una inconsistencia en el mapeo MITRE automático de
   Wazuh entre el evento individual y la regla de correlación.
2. **[Gap Analysis — Emulación de Discovery post-explotación](incident-reports/02-caldera-gap-analysis-discovery.md)**
   — Ejecución de técnicas MITRE ATT&CK (Discovery/Defense Evasion) contra
   el Domain Controller, con hallazgo de una brecha real entre recolección
   de telemetría y reglas de correlación activas en el SIEM.

## Documentación técnica completa

Ver [docs/arquitectura-documentacion-tecnica.md](docs/arquitectura-documentacion-tecnica.md)
para el detalle completo de hardware, topología de red, inventario de VMs
y estado de agentes.

## Video demo

[Link al video](media/video-demo-link.md) — resumen del proyecto y guía de
navegación del repositorio.

## Stack técnico

Proxmox VE · pfSense · Wazuh · Sysmon · CALDERA · Active Directory (Windows
Server) · MITRE ATT&CK

## Sobre mí

[2-3 líneas tuyas: quién sos, qué buscás, contacto/LinkedIn]
