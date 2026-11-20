# Integración Identidad (G1) → SIEM · Contrato de validación de tokens

## Alcance y estado de implementación

Este contrato especifica cómo autentica el SIEM las peticiones a sus operaciones protegidas a través del Módulo 1 (Identidad y secretos). Cubre las operaciones protegidas, la validación de tokens, la identidad de los servicios, las respuestas, la indisponibilidad de Identidad y lo que deben hacer los productores y los consumidores. Corresponde a SEM-132 (HU18 / SEM-34) y se registra en la revisión de contratos de SEM-116 (HU20). La matriz de permisos por rol se cierra en SEM-35 (HU19) y SEM-141.

El SIEM actúa como **consumidor** de G1. La fuente de verdad del proveedor es el [contrato de Identidad](../../01-identidad/contract/openapi.yaml), versión **1.3.0**, y su resumen en [`shared/auth-contract.md`](../../../shared/auth-contract.md). Este documento no redefine esos endpoints: fija cómo los usa el SIEM y qué cambios se piden a G1. La referencia de código es el commit `5deed65`. La referencia identifica versiones de código; no acredita ninguna ejecución de integración.

| Aspecto | Estado actual (`0.3.0-sprint2`) | Especificación de integración |
| --- | --- | --- |
| Autenticación en el SIEM | Ninguna | Obligatoria en `POST /events`, `GET /events`, `GET /alerts` y `GET /alerts/{id}` |
| `GET /health` | Público | Se mantiene público |
| Validación del token | No aplica | `GET /auth/validate` de G1 en cada petición protegida, sin caché |
| Identidad de los servicios | No aplica | Una cuenta por módulo con rol `servicio` (propuesta A) o la cuenta `servicio` compartida (propuesta B) |
| Identidad no disponible | No aplica | 503 `IDENTITY_UNAVAILABLE`, sin conceder acceso |
| Formato de eventos y alertas | Esquema común | **Sin cambios** |
| Contenedor de errores | `{"error": {"code", "message"}}` | Se conserva |

**Estado: propuesta pendiente de ratificar con G1.** La autenticación no está implementada todavía en el SIEM; se implementa en SEM-133.

## Operaciones protegidas

| Operación | ¿Protegida? | Quién la usa | Rol esperado (propuesta para SEM-35) |
| --- | --- | --- | --- |
| `GET /health` | **No** | CI, healthcheck del compose, vista de salud del Dashboard | No aplica |
| `POST /events` | Sí | G2 IDS, G3 Honeypot, G4 Escáner, G8 Pentesting | `servicio` |
| `GET /events` | Sí | G7 Dashboard (analista) | `analista`, `admin` |
| `GET /alerts` | Sí | G6 SOAR (servicio), G7 Dashboard (analista) | `servicio`, `analista`, `admin` |
| `GET /alerts/{id}` | Sí | G6 SOAR, G7 Dashboard | `servicio`, `analista`, `admin` |

En SEM-34 solo se comprueba la identidad; los roles se aplican en SEM-35. La matriz se incluye aquí para que G1 la revise junto al resto del contrato.

## Petición y transporte

### Del cliente al SIEM

```http
POST /events
Content-Type: application/json
Accept: application/json
Authorization: Bearer <jwt emitido por G1>
```

Las operaciones de lectura llevan la misma cabecera `Authorization`. El token lo emite G1 con `POST /auth/login`: JWT HS256 con los claims `sub`, `role`, `user_id`, `iat`, `exp` y `jti`, que caduca a los **30 minutos** y no tiene *refresh*.

### Del SIEM a Identidad

```http
GET /auth/validate
Authorization: Bearer <el mismo token recibido>
```

| Entorno | Destino (`IDENTITY_URL`) | Condición |
| --- | --- | --- |
| Servicios dentro de la red Docker compartida | `http://identidad:80` | Servicio `identidad` sano en el compose |
| Ambos procesos en el mismo equipo | `http://localhost:8001` | Puerto de Identidad accesible |
| Tests del SIEM | *Stub* de Identidad (WireMock o MockWebServer) | Solo en el perfil de pruebas |

El SIEM **no** decodifica ni verifica el JWT por su cuenta: la clave de firma no sale de G1 y el contrato de G1 exige validar con `GET /auth/validate`. *Timeouts*: 1 s de conexión y 2 s de lectura (`IDENTITY_TIMEOUT_MS`). No se guardan en caché las validaciones: así, un `POST /auth/logout` tiene efecto inmediato en el SIEM.

## Identidad de los servicios

G1 tiene hoy **una sola cuenta de servicio**, `servicio`. Con ella:

- el SIEM no puede comprobar que un evento con `source: "ids"` lo publica de verdad el IDS;
- si se filtra la contraseña en un módulo, quedan expuestos todos;
- la auditoría de G1 no distingue qué módulo hace cada acceso.

**Propuesta A (preferida).** G1 precarga una cuenta por módulo con rol `servicio` y una variable de entorno por contraseña. Es un cambio compatible para G1 (propuesta de versión 1.4.0): solo añade cuentas.

| Cuenta | Variable en G1 | Módulo | `source` permitido en `POST /events` |
| --- | --- | --- | --- |
| `svc-ids` | `SERVICE_PASSWORD_IDS` | G2 IDS | `ids` |
| `svc-honeypot` | `SERVICE_PASSWORD_HONEYPOT` | G3 Honeypot | `honeypot` |
| `svc-escaner` | `SERVICE_PASSWORD_ESCANER` | G4 Escáner | `scanner` |
| `svc-pentesting` | `SERVICE_PASSWORD_PENTESTING` | G8 Pentesting | `pentesting` |
| `svc-soar` | `SERVICE_PASSWORD_SOAR` | G6 SOAR | No publica eventos |

Con la propuesta A, el SIEM comprueba en SEM-35 que el `username` validado corresponde al `source` del evento; si no corresponde, responde 403 `SOURCE_MISMATCH` sin insertar nada.

**Propuesta B (alternativa si G1 no llega antes del 26/11).** Se mantiene la cuenta `servicio` compartida. El SIEM solo comprueba el rol `servicio` y no puede atribuir el `source`. La limitación se registra en el ROAM como *Accepted*, con G1 como responsable y una fecha de revisión.

**Riesgo trasladado a G1, sin bloquear el acuerdo:** cualquier cuenta con rol `servicio` puede leer todos los secretos (`GET /secrets/{clave}`). Repartir cuentas a más módulos amplía lo que queda expuesto si una se ve comprometida. Se registra en el ROAM.

## Validación y respuestas

### Respuesta de Identidad → resultado en el SIEM

| Situación | Llamada a G1 | Respuesta del SIEM | Código |
| --- | --- | --- | --- |
| Ruta `GET /health` | No | 200, como hasta ahora | No aplica |
| Sin cabecera `Authorization`, o sin formato `Bearer <token>` | No | 401 con `WWW-Authenticate: Bearer` | `UNAUTHENTICATED` |
| G1 responde 200 con `valid: true`, `username` y `role` | Sí | La petición continúa | No aplica |
| G1 responde 401 (token inválido, expirado, revocado o ausente) | Sí | 401 con `WWW-Authenticate: Bearer` | `UNAUTHENTICATED` |
| G1 responde 200 sin `valid: true`, o con un cuerpo que no se puede leer | Sí | 503 | `IDENTITY_UNAVAILABLE` |
| G1 responde 5xx, no responde a tiempo o rechaza la conexión | Sí | 503 con `Retry-After: 30` | `IDENTITY_UNAVAILABLE` |
| `IDENTITY_URL` no configurada | No | 503 | `IDENTITY_UNAVAILABLE` |

Los errores conservan el contenedor común:

```json
{
  "error": {
    "code": "UNAUTHENTICATED",
    "message": "Missing, invalid, expired or revoked token"
  }
}
```

```json
{
  "error": {
    "code": "IDENTITY_UNAVAILABLE",
    "message": "The identity service is not available"
  }
}
```

El 503 por Identidad se distingue del 503 por almacenamiento (`STORAGE_UNAVAILABLE`) por `error.code`. La autenticación se comprueba **antes** de validar o almacenar el evento: un `POST /events` rechazado por autenticación no inserta ninguna fila ni genera ninguna alerta.

El SIEM **no** registra el token ni lo reenvía a ningún otro servicio. En sus logs solo anota el `username`, el `role` y el resultado de la validación.

### Indisponibilidad de Identidad

El SIEM es *fail-closed*: si no puede confirmar la identidad, no concede acceso. No hay una opción para desactivar la autenticación fuera del perfil de pruebas. `GET /health` sigue respondiendo 200 aunque Identidad esté caída, para no confundir la salud del SIEM con la de G1. En el compose, `siem` pasa a depender de `identidad` con `condition: service_healthy`.

## Conducta esperada de productores y consumidores

Estas filas amplían las tablas de respuestas ya acordadas con G3 ([HU5](../docs/hu5-integracion-honeypot.md)) y G4 ([contrato del Escáner](scanner-events.md)), y se aplican igual a G2, G6, G7 y G8:

| Respuesta del SIEM | Significado | Conducta esperada |
| --- | --- | --- |
| 401 `UNAUTHENTICATED` | Token ausente, inválido, expirado o revocado | Hacer login en G1 **una vez** y reintentar **una vez**. Si vuelve a recibir 401, registrar el fallo y no repetir en bucle: G1 bloquea el login tras 5 fallos en 15 min (`429`) |
| 403 (SEM-35) | Token válido, pero el rol o la cuenta no permiten la operación | Registrar el fallo y no reintentar |
| 503 `IDENTITY_UNAVAILABLE` | El SIEM no ha podido validar con G1 | Mantener el evento pendiente y reintentar con espera creciente, conservando identidad y contenido. El reenvío es seguro: un reenvío idéntico con la misma `(source, event_id)` devuelve 200 |

Para no recibir 401 por caducidad, el cliente puede renovar el login antes de los 30 minutos (por ejemplo, a los 25). Las credenciales de servicio salen de variables de entorno (`SIEM_AUTH_USER`, `SIEM_AUTH_PASSWORD`) o de un `.env` ignorado por Git. **El repositorio es público: no se suben credenciales.**

### Estado actual por módulo (commit `5deed65`)

| Grupo | Papel | Estado | Cambio necesario |
| --- | --- | --- | --- |
| G2 IDS | Productor | Envío automático pendiente (IDS-52) | Incluir login y Bearer al implementarlo |
| G3 Honeypot | Productor | `SiemSenderService` hace POST sin `Authorization` | Login, Bearer y tratamiento de 401/503 |
| G4 Escáner | Productor | `jobs.py` hace POST sin `Authorization` | Login, Bearer y tratamiento de 401/503 |
| G8 Pentesting | Productor (opcional) | Publicación al SIEM no conectada | Incluir login y Bearer si publica |
| G6 SOAR | Consumidor | Lee un token fijo de `SIEM_TOKEN`, que caduca a los 30 min | Login con su cuenta de servicio; no tratar 401/503 como «no hay alertas» |
| G7 Dashboard | Consumidor | Envía el token del analista; nginx (`/api/siem/`) reenvía la petición al SIEM | Confirmar en la prueba real que llega `Authorization`; tratar el 503; quitar el valor por defecto `"token-de-prueba"` |

## Acuerdos pendientes con G1

Preguntas enviadas a G1 el 19/11/2026:

| # | Pregunta | Propuesta de G5 | Respuesta de G1 |
| --- | --- | --- | --- |
| P1 | ¿Podéis provisionar cuentas distintas `svc-ids`, `svc-honeypot`, `svc-escaner`, `svc-pentesting` y `svc-soar`, con rol `servicio`, antes del 26/11? | Propuesta A. G5 aplica los permisos y comprueba la correspondencia entre identidad y `source` | |
| P2 | ¿Qué canal privado y qué fecha utilizaréis para entregar las credenciales? | Canal privado, nunca el repositorio | |
| P3 | ¿Existen límites de carga o frecuencia para `/auth/validate`? | Comprobar juntos el escenario real antes de introducir caché | |
| P4 | ¿Se mantienen las respuestas publicadas 200, 401 y 500? | El SIEM trata cualquier 5xx o respuesta incompatible como «no disponible» | |
| P5 | ¿Se mantienen los 30 minutos de caducidad y la obtención de nuevos tokens mediante login? | Renovar con login antes de que caduque | |
| P6 | ¿Cómo se provisionaría el secreto `siem_db_password` y qué restricciones de lectura por cuenta tendrá? | Ver la sección siguiente | |

## Secreto de base de datos del SIEM

G5 propone custodiar en G1 la contraseña de PostgreSQL del SIEM bajo la clave `siem_db_password`. El nombre cumple el formato de claves de G1 (`^[A-Za-z0-9_.-]{1,100}$`). Quién la recupera para el despliegue se concreta con G7 en SEM-129.

Situación en el código publicado de G1 (`5deed65`):

- No existe un endpoint para crear secretos. G1 solo precarga tres claves fijas desde variables de entorno: `db_password`, `api_key` y `jwt_secret`. Añadir `siem_db_password` requiere un cambio en G1, por ejemplo una variable `SECRET_SIEM_DB_PASSWORD`.
- `GET /secrets/{clave}` solo responde al rol `servicio`, y cualquier cuenta con ese rol puede leer cualquier secreto existente. No hay restricción por cuenta.
- Quien recupere el secreto necesita una cuenta con rol `servicio`. Ninguna de las cuentas de P1 pertenece al SIEM ni a G7: falta decidir si será `svc-siem` o una cuenta de G7.
- Si el SIEM lee la contraseña de G1 al arrancar, no puede arrancar sin Identidad. Encaja con la dependencia `service_healthy` del compose, y G7 debe tenerlo en cuenta para el despliegue.

La falta de restricción de lectura por cuenta se registra en el ROAM como riesgo, con G1 como responsable.

## Compatibilidad y despliegue

Exigir autenticación es un **cambio incompatible** del contrato del SIEM: los productores y consumidores que hoy llaman sin token recibirán 401. Para el registro de cambios de contrato del SoS:

| Campo | Valor |
| --- | --- |
| Contrato | SIEM `0.3.0-sprint2` → `0.4.0` |
| Cambio | `POST /events`, `GET /events`, `GET /alerts` y `GET /alerts/{id}` exigen `Authorization: Bearer`; nuevos códigos 401 `UNAUTHENTICATED` y 503 `IDENTITY_UNAVAILABLE` |
| Motivo | DoD de integración: «la autenticación se hace siempre a través del Módulo 1» (SEM-34 / HU18) |
| Equipos afectados | G1 (proveedor), G2, G3, G4 y G8 (productores), G6 y G7 (consumidores) |
| Fecha efectiva | Contrato cerrado el **26/11**. Autenticación activa en el compose antes del Integration Day. Recorrido autenticado verificado el **30/11** |
| Dependencias en Jira | Si se aplica la propuesta A, SEM-34 «es bloqueada por» la tarjeta de G1 (proyecto AAA) |

Se actualizan a la vez el [OpenAPI](openapi.json) (esquema `bearerAuth` y respuestas 401/503) y este documento. El formato de eventos y alertas no cambia.

## Criterios verificables de integración

| Caso | Resultado exigido |
| --- | --- |
| `GET /health` sin token | 200 |
| Operación protegida sin `Authorization` | 401 `UNAUTHENTICATED`, sin llamar a G1 |
| `Authorization` sin formato `Bearer` | 401 `UNAUTHENTICATED` |
| Token válido emitido por G1 | La operación responde como hasta ahora |
| Token con la firma alterada | 401 `UNAUTHENTICATED` |
| Token expirado (más de 30 min) | 401 `UNAUTHENTICATED` |
| Token revocado con `POST /auth/logout` | 401 `UNAUTHENTICATED` en la petición siguiente |
| `POST /events` rechazado por autenticación | Ninguna fila insertada y ninguna alerta generada |
| Identidad caída, lenta o devolviendo 5xx | 503 `IDENTITY_UNAVAILABLE` y acceso denegado |
| Identidad recuperada | Las peticiones con token válido vuelven a ser aceptadas |
| Logs del SIEM | Sin tokens ni contraseñas |
| Productor real (G3 o G4) en el compose | Login, envío autenticado y almacenamiento correlacionados por `event_id` |
| SOAR y Dashboard en el compose | Leen alertas con su token; con token inválido reciben 401 |

Las pruebas unitarias y de integración con *stub* de Identidad corresponden a SEM-134. El recorrido con servicios reales corresponde a SEM-135. Los fallos de Identidad y la regresión corresponden a SEM-136.

## Contrato ratificado con G1

*Pendiente.* Cuando G1 confirme, se completa con la fecha, la propuesta elegida (A o B), las respuestas a P1–P6 y la evidencia (captura de Teams o minuta del SoS) adjunta en SEM-132.
