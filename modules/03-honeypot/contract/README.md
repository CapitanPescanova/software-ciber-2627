# Contrato de API

# Contrato de Eventos del Honeypot

> **Versión provisional, pendiente del visto bueno del grupo 5**

Este documento define la estructura del evento de seguridad que el módulo honeypot (`03-honeypot`) envía al SIEM tras registrar un intento de ataque.

## Estructura de campos

| Campo | Tipo | Obligatorio | Descripción |
| :--- | :--- | :---: | :--- |
| `event_id` | String (UUIDv4) | Sí | Identificador único del evento para trazabilidad en el SIEM. |
| `timestamp` | String (ISO 8601 UTC) | Sí | Fecha y hora exacta en la que se registró el intento. |
| `source` | String | Sí | Identificador del honeypot origen (ej. `honeypot-login-03`). |
| `event_type` | String (Enum) | Sí | Tipo de ataque detectado (`fuerza_bruta`, `credenciales_por_defecto`, `escaneo`). |
| `severity` | String (Enum) | Sí | Nivel de gravedad del evento (`baja`, `media`, `alta`, `critica`). |
| `source_ip` | String (IPv4) | Sí | Dirección IP origen desde la que se realiza la petición. |
| `service` | String | Sí | Servicio o protocolo objetivo atacado (ej. `http-login`). |
| `details` | Object | Sí | Información detallada del intento (endpoint, credenciales probadas, etc.). |

### Valores de `event_type`
- `fuerza_bruta`: Múltiples intentos repetidos o combinaciones comunes de credenciales.
- `credenciales_por_defecto`: Intentos con pares usuario/contraseña estándar de fábrica (admin/admin, root/toor).
- `escaneo`: Pruebas de reconocimiento de rutas, cabeceras o peticiones de sondeo sin credenciales útiles.

## Ejemplos de eventos
Los ejemplos validados de cada tipo de evento se encuentran en formato JSON en `contract/examples/`:
- `fuerza_bruta.json`
- `credenciales_por_defecto.json`
- `escaneo.json`