## 💻 Hardware & Topología de Red

### 1. Servidor de Virtualización (Bare-Metal)

* **Equipo:** Lenovo ThinkPad W510
* **CPU:** Intel Core i7 Q820 (4C / 8T)
* **RAM:** 32 GB DDR3
* **Almacenamiento:** 980 GB SSD
* **GPU:** NVIDIA Quadro FX 880M
* **Hypervisor:** Proxmox VE 9.2.11 (Kernel 7.0.14-14-pve)
* **IP de Gestión PVE:** `192.168.1.200:8006`

### 2. Estación de Conexión y Manejo

* **Equipo:** Asus N56V
* **CPU:** Intel Core i5-3210M (2C / 4T)
* **RAM:** 16 GB DDR3
* **Almacenamiento:** 480 GB SSD
* **SO Host:** Windows 10 Pro 64-bit

### 3. Infraestructura de Red Física

* **Gateway Principal (WAN):** Router Starlink 
* **Desktop Switch (WAN):** Switch TP-Link 5-port TL-SF1005D
1. Conexión de Starlink al DS (Desktop Switch) por el puerto Ethernet 5.
2. Lenovo ThinkPad W510 conectada al puerto 1.
3. Asus N56V conectada al puerto 2.

---

## 🗺️ Segmentación de Red (VLANs L2/L3 en pfSense)

| VLAN Tag | Nombre / Función | Subred CIDR | Gateway pfSense | Componentes / Objetivos |
| --- | --- | --- | --- | --- |
| **VLAN 1** | **SOC Core / Mgmt** | `10.10.1.0/25` | `10.10.1.1` | Wazuh SIEM, CALDERA, Nessus, Security Onion, Debian Admin |
| **VLAN 10** | **Targets / DMZ** | `10.10.10.0/25` | `10.10.10.1` | Microservicios, Objetivos vulnerables Linux / Metasploitable |
| **VLAN 20** | **Active Directory** | `10.10.20.0/25` | `10.10.20.1` | Windows Server DC (VM 109), Endpoints Windows Client (VM 108) |
| **VLAN 30** | **Microservicios / Web** | `10.10.30.0/25` | `10.10.30.1` | Ubuntu Server + Docker + Portainer + Aplicaciones Web |

---

## 📐 Matriz de Máquinas Virtuales (Proxmox VE)

| VM ID | Name | OS / Rol | vCPU / RAM / Disk | Interface / Tag |
| --- | --- | --- | --- | --- | --- |
| `100` | `pfSense-Firewall` | pfSense Firewall / Router | 2 Cores / 2.00 GiB / 20 GB | `vmbr0` (WAN) & `vmbr1` (Trunk) |
| `101` | `Debian-vlan1` | Debian Admin Station (GUI) | 3 Cores / 4.00 GiB / 30 GB | `vmbr1` (VLAN Tag: 1) |
| `102` | `Ubuntu-vlan30` | Ubuntu Server (Docker Host) | 3 Cores / 3.02 GiB / 50 GB | `vmbr1` (VLAN Tag: 30) | 
| `103` | `Prod-ms2-vlan10` | Microservicios Target / DMZ | 2 Cores / 2.00 GiB / 20 GB | `vmbr1` (VLAN Tag: 10) | 
| `104` | `Prod-Wazuh-vlan1` | Ubuntu Server (Wazuh SIEM) | 4 Cores / 8.00 GiB / 30 GB | `vmbr1` (VLAN Tag: 1) | 
| `105` | `Prod-Nessus-vlan1` | Nessus Vulnerability Scanner | 4 Cores / 4.00 GiB / 30 GB | `vmbr1` (VLAN Tag: 1) | 
| `106` | `Prod-Caldera-vlan1` | CALDERA Adversary Emulation | 4 Cores / 3.02 GiB / 20 GB | `vmbr1` (VLAN Tag: 1) | 
| `107` | `Prod-SO-vlan1-55` | Security Onion (NSM/SOAR) | 4 Cores / 8.00 GiB / 50 GB | `vmbr1` (VLAN Tag: 1) | 
| `108` | `Prod-Win10-Client` | Windows 10 Home (Target Endpoint) | 4 Cores / 4.00 GiB / 50 GB | `vmbr1` (VLAN Tag: 20) | 
| `109` | `Prod-DC-WinServer-vlan20` | Windows Server 2025 (Domain Controller) | 2 Cores / 4.00 GiB / 40 GB | `vmbr1` (VLAN Tag: 20) | 

---

## 🔍 Inventario Detallado de Servicios e IPs Internas

| VM ID | Nombre VM                  | IP Asignada   | Servicio / Aplicación Interna                | Puerto / URL Acceso                 | Notas / Estado                              |
| ----- | -------------------------- | ------------- | -------------------------------------------- | ----------------------------------- | ------------------------------------------- |
| `100` | `pfSense-Firewall`         | `10.10.1.1`   | WebGUI Gateway & Router                      | `https://10.10.1.1`                 | Enrutamiento Inter-VLAN                     |
| `101` | `Debian-vlan1`             | `10.10.1.50`  | Entorno de Administración SOC                | `SSH / RDP / Web`                   | Estación Red & Blue Team (VLAN 1)           |
| `102` | `Ubuntu-vlan30`            | `10.10.30.50` | Portainer Engine (Host Docker)               | `https://10.10.30.50:9443`          | Gestor de Contenedores                      |
| `102` | `Ubuntu-vlan30`            | `10.10.30.40` | Nginx Reverse Proxy                          | `http://10.10.30.40`                | Contenedor en Docker                        |
| `102` | `Ubuntu-vlan30`            | `10.10.30.41` | bWAPP (Buggy Web App)                        | `http://10.10.30.41`                | Target Vulnerable Web (Contenedor)          |
| `102` | `Ubuntu-vlan30`            | `10.10.30.42` | OWASP WebGoat                                | `http://10.10.30.42:8080`           | Target Vulnerable Web (Contenedor)          |
| `102` | `Ubuntu-vlan30`            | `10.10.30.43` | DVWA (Damn Vulnerable Web App)               | `http://10.10.30.43`                | Target Vulnerable Web (Contenedor)          |
| `103` | `Prod-ms2-vlan10`          | `10.10.10.50` | Metasploitable2 / Target DMZ                 | `http://10.10.10.50`                | Objetivo de Red / Explotación               |
| `104` | `Prod-Wazuh-vlan1`         | `10.10.1.51`  | Wazuh Dashboard & Indexer                    | `https://10.10.1.51`                | Recopilación de telemetría y SIEM           |
| `105` | `Prod-Nessus-vlan1`        | `10.10.1.52`  | Nessus Scanner WebUI                         | `https://10.10.1.52:8834`           | Escaneo activo de vulnerabilidades          |
| `106` | `Prod-Caldera-vlan1`       | `10.10.1.54`  | CALDERA Server                               | `http://10.10.1.54:8888`            | Emulación de amenazas y ataques             |
| `107` | `Prod-SO-vlan1-55`         | `10.10.1.55`  | Security Onion Console                       | `https://10.10.1.55`                | Monitoreo NSM / SOAR / Zeek / Suricata      |
| `108` | `Prod-Win10-Client`        | `10.10.20.51` | Windows 10 Endpoint Telemetry                | `Agente Wazuh 4.7.5 / Sysmon 15.15` | Agente ID 004 (Domain Joined: `corp.local`) |
| `109` | `Prod-DC-WinServer-vlan20` | `10.10.20.10` | Active Directory & DNS Server (`corp.local`) | `TCP 53, 88, 135, 389, 445`         | Primary Domain Controller (AD DS)           |


---
