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

> En reconstrucción — ver /archive para la versión anterior.

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
