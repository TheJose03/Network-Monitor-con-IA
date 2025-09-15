# Monitor de Red - Especificaciones

> **¡ADVERTENCIA IMPORTANTE!**
> 
> **La versión automática BLOQUEARÁ TODAS LAS CONEXIONES ESTABLECIDAS (ACTIVAS) SIN PREGUNTAR.**
> 
> **Solo para usuarios avanzados** con experiencia en:
> - Configuración de firewalls
> - Resolución de problemas de red
> - Gestión de listas blancas/negras
> 
> **Puede interrumpir servicios críticos si la usas sin ser experto .**

## Descripción General
Aplicación de seguridad que monitorea conexiones de red en tiempo real, desarrollada en Go para Windows.

## Características Clave

- **Monitoreo en Tiempo Real**
  - Conexiones TCP activas
  - Procesos asociados
  - Detección de anomalías

- **Control de Acceso**
  - Lista Blanca (IPs permitidas)
  - Lista Negra (IPs/procesos bloqueados)
  - Lista de Desconocidas

- **Geolocalización**
  - Ubicación de IPs remotas
  - Caché integrado
  - Límite de consultas API

- **Firewall**
  - Bloqueo automático/manual
  - Integración con Windows Firewall
  - Registro detallado

## Estructura del Proyecto

```
/
├── network-monitor_Auto/    # Versión automática (bloqueo sin confirmación)
├── network-monitor_Manual/  # Versión manual (requiere aprobación)
├── logs/                   # Archivos de registro
├── hashes/                 # Hashes de ejecutables
├── whitelist.txt           # IPs permitidas
├── blacklist.txt           # IPs/procesos bloqueados
└── log_conexiones.*        # Registros (TXT, CSV, JSON)
```

## Componentes Principales

### 1. Almacenamiento (Storage)
- Gestión de archivos de configuración
- Almacenamiento persistente de listas y registros
- Sincronización segura para acceso concurrente

### 2. Geolocalizador (GeoLocator)
- Consulta de información geográfica de IPs
- Sistema de caché para mejorar el rendimiento
- Control de tasa de consultas

### 3. Firewall
- Bloqueo de conexiones no autorizadas
- Integración con el sistema operativo
- Registro de eventos de bloqueo

### 4. Monitor de Conexiones
- Monitoreo continuo de conexiones de red
- Detección de anomalías
- Gestión de eventos críticos

## Archivos de Configuración

### whitelist.txt
```
# Ejemplo de lista blanca
192.168.1.1
10.0.0.1
```

### blacklist.txt
```
# Formato: IP | Proceso | Organización | Motivo | Efectos
1.1.1.1 | malware.exe | Hacker Inc. | Malware | Ninguno
2.2.2.2 | * | Red sospechosa | Bloqueo preventivo | Posible pérdida de servicio
```

## Requisitos
- Windows 7 o superior
- Privilegios de administrador
- Conexión a Internet (para geolocalización)

## Uso Básico
1. Ejecutar como administrador
2. Monitorear conexiones
3. Revisar los logs 
4. Actualizar listas según sea necesario

## Seguridad
- Requiere permisos elevados
- Monitorear logs regularmente
- Mantener listas actualizadas

## Versiones Disponibles

### 1. Versión Automática
- **Bloqueo automático** sin confirmación
- **Ideal para**:
  - Usuarios expertos
  - Protección estricta
  - Respuesta inmediata
- **Riesgos**:
  - Bloqueo de servicios legítimos
  - Requiere configuración cuidadosa

### 2. Versión Manual
- **Control total** del usuario
- **Ideal para**:
  - Entornos que requieren revisión
  - Usuarios que prefieren control total
  - Minimizar falsos positivos

## Limitaciones
- Posibles falsos positivos/negativos
- Rendimiento en sistemas con muchas conexiones
- Dependencia de permisos UAC
  
## Por estas razones no lo coloco de codigo abierto:

https://www.youtube.com/watch?v=hbbXzuLOyJ0

https://www.youtube.com/watch?v=alfIxtD9CKM
