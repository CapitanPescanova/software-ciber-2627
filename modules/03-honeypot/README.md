# Módulo 3 · Honeypot inteligente

- *Equipo propietario:* `equipo-03-honeypot` (Winnie de Pot)
- *Puerto:* `8003`

## Qué hace
Tres servicios señuelo: un login web falso, un SSH falso y un FTP falso. Todos rechazan siempre el acceso. Cada intento se guarda en una base de datos H2 (IP, hora en UTC, servicio, usuario y contraseña o comando), se clasifica (por ahora, fuerza bruta) y se envía al SIEM del grupo 5.

## Qué expone
- `GET /login`: la página del login falso.
- `POST /login`: recibe el intento, lo guarda y lo envía al SIEM.
- `GET /health`: devuelve `{"status":"ok","module":"03-honeypot"}`.
- SSH señuelo en el puerto `2222` y FTP señuelo en el `2121`. En Docker, los tres puertos solo se publican en `127.0.0.1`.
- Hacia el SIEM: `POST /events` con el formato común de evento (ver `contract/`).

## Qué consume
Nada obligatorio. Si el SIEM no responde, los intentos se guardan igual. Para probar el envío hay un mock en `mocks/`.

## Cómo arrancarlo
- *Con Docker* (desde la raíz del repo): `docker compose up --build honeypot` → `http://localhost:8003/login`
- *Sin Docker* (desde `modules/03-honeypot`, con Java 25 o superior): `./mvnw spring-boot:run` → `http://localhost:8080/login`
- *SSH:* `ssh -p 2222 root@localhost` · *FTP:* cualquier cliente FTP contra `localhost:2121`
- *Pruebas:* `./mvnw test`
- *Mock del SIEM:* `java mocks/SiemMockServer.java` (escucha `POST /events` en el puerto `8081`)

## Perfil dev
La página `/attempts` (ver y borrar intentos) solo existe arrancando con
`./mvnw spring-boot:run -Dspring-boot.run.profiles=dev`.
*Nunca* poner `SPRING_PROFILES_ACTIVE=dev` en Docker: dejaría las credenciales capturadas a la vista.

## Estado
- Hecho: login web, FTP y SSH señuelo, registro de intentos, envío al SIEM, detección de fuerza bruta (`HP-12`), puertos solo en local y ejecución sin root.
- En curso (Sprint 2): credenciales por defecto (`HP-25`), registro de los intentos SSH (`HP-67`), límites de peticiones y de recursos (`HP-32`) y tráfico de salida solo hacia el SIEM (`HP-68`).

## Configuración de la detección de fuerza bruta

Se configura en `src/main/resources/application.properties`:

| Propiedad | Valor por defecto | Qué hace |
| --- | --- | --- |
| `honeypot.fuerza-bruta.max-intentos` | 5 | Número de intentos de una misma IP a partir del cual se considera fuerza bruta |
| `honeypot.fuerza-bruta.ventana-segundos` | 60 | Ventana de tiempo, en segundos, en la que se cuentan esos intentos |

Los intentos se cuentan por IP sumando todos los servicios señuelo. Solo cuentan los intentos con contraseña: en el FTP, los comandos `USER`, `LIST`, etc. se registran pero no suman. Se etiqueta como `fuerza_bruta` a partir del intento que supera el máximo; los anteriores no se cambian.

Al SIEM se envía como `event_type` la etiqueta guardada en el intento. Si no tiene etiqueta, se envía `intento_login` (acuerdo con el grupo 5, ver `contract/`).

## Plan de pruebas (Sprint 2)

Cada criterio de aceptación del sprint tiene al menos una prueba. Las automáticas se lanzan con `.\mvnw.cmd test` (Windows) o `./mvnw test` desde `modules/03-honeypot`, y la CI las pasa en cada PR (job *Honeypot Tests*). Las manuales se hacen antes de cerrar la historia, y el PO deja en Jira lo que ha comprobado.

- **Unitaria:** prueba una clase sola, con mocks.
- **Integración:** arranca Spring con la BD H2 en memoria y los servicios señuelo de verdad.
- **Manual:** con un cliente FTP o SSH, o revisando el `docker-compose.yml` y el contenedor.

En el Sprint 3 el grupo 8 hará pentesting contra el honeypot.

| Historia | Criterio | Prueba | Tipo | CI | Estado |
| --- | --- | --- | --- | --- | --- |
| HP-12 | El sexto intento de una IP en 1 minuto es `fuerza_bruta` | `FuerzaBrutaIntegracionTest`: `elSextoIntentoEsFuerzaBrutaYLosAnterioresNoCambian` y `enElFtpSoloCuentanLosComandosPass` | Integración | Sí | Hecho (falta el SSH, `HP-67`) |
| HP-12 | Los 5 primeros conservan su tipo y no se reenvían | Mismo test y `EventoMapperTest` | Integración y unitaria | Sí | Hecho |
| HP-12 | 5 intentos o menos, o separados, no son fuerza bruta | `cincoIntentosEnUnMinutoNoSonFuerzaBruta` y `seisIntentosSeparadosMasDeUnMinutoNoSonFuerzaBruta` | Integración | Sí | Hecho |
| HP-12 | El umbral se cambia en la configuración | `FuerzaBrutaConfigTest` y `ClasificadorAtaquesServiceTest` | Unitaria | Sí | Hecho |
| HP-6 | Banner de bienvenida | `FtpHoneypotIntegrationTest` comprueba el 220 | Integración | Sí | Hecho |
| HP-6 | El acceso siempre se rechaza | Cliente FTP contra `127.0.0.1:2121`, el PASS devuelve 530 | Manual | No | Por confirmar |
| HP-6 | USER, PASS y LIST quedan registrados | `FtpHoneypotIntegrationTest` (LIST, CWD y RETR) y `FuerzaBrutaIntegracionTest` (USER y PASS) | Integración | Sí | Hecho |
| HP-6 | Nunca devuelve archivos reales | `FtpHoneypotIntegrationTest`: RETR sin login devuelve 530 | Integración | Sí | Hecho |
| HP-2 | Banner realista y pide credenciales | `ssh -p 2222 prueba@127.0.0.1`: sale `OpenSSH_8.9p1 Ubuntu` y pide contraseña | Manual | No | Hecho |
| HP-2 | Siempre rechaza y nunca da terminal | Mismo `ssh`: vuelve a pedir la contraseña | Manual | No | Hecho |
| HP-2 | Registra usuario y contraseña | Pendiente (`HP-67`) | | | Pendiente |
| HP-2 | Usa una librería SSH existente | `pom.xml`: Apache MINA SSHD | Revisión | No | Hecho |
| HP-2 (HP-69) | La huella SSH no cambia al recrear el contenedor | `ssh-keyscan -p 2222 127.0.0.1` antes y después de `docker compose down` y `up` | Manual | No | Hecho |
| HP-25 | Una credencial de la lista se etiqueta `credenciales_por_defecto` | `ClasificadorAtaquesServiceTest` y `CredencialesPorDefectoIntegracionTest` | Unitaria e integración | Sí | Pendiente (PR de `HP-82`, `HP-83` y `HP-84`) |
| HP-25 | La lista se amplía sin cambiar el código | `CredencialesPorDefectoConfigTest` | Unitaria | Sí | Pendiente (PR de `HP-82`, `HP-83` y `HP-84`) |
| HP-30 | Solo expone los puertos señuelo y solo en el entorno | `docker compose ps`: 8003, 2121 y 2222 solo en `127.0.0.1` (PR #20) | Manual | No | Hecho |
| HP-30 | No corre como root ni ve credenciales de otros módulos | `docker compose exec honeypot id` (usuario `http`) y revisar sus variables de entorno | Manual | No | Por confirmar |
| HP-30 | Solo sale tráfico hacia el SIEM | Pendiente (`HP-68`) | Manual | No | Pendiente |
| HP-32 | Más de 10 peticiones por segundo devuelven 429 | Pendiente (`HP-71`) | | | Pendiente |
| HP-32 | Pasan al menos 6 antes de rechazar | Pendiente (`HP-71`) | | | Pendiente |
| HP-32 | Resumen de rechazos en la BD | Pendiente (`HP-88`) | | | Pendiente |
| HP-32 | Límites de CPU y memoria | Revisar el compose y `docker stats` (`HP-72`) | Manual | No | Pendiente |
| HP-32 | El resto de módulos sigue funcionando | Lanzar una ráfaga y comprobar el `/health` de otros módulos (`HP-73`) | Manual | No | Pendiente |