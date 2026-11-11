# ISBECORE-478 — Despliegue del endurecimiento de la integración TSA

Procedimiento para el operador de Coolify después del merge de
`fix/isbecore-478-tsa-hardening`. Detalle técnico en
[tsaservice/README.md](../tsaservice/README.md). Estado de los criterios de
aceptación en [ISBECORE-478-acceptance.md](ISBECORE-478-acceptance.md).

## 1. Qué cambia y por qué importa el orden

| Antes (versión desplegada hoy) | Después |
|-------------------------------|---------|
| Al sellar se usaban **siempre** el usuario, la contraseña y la URL (`pre-api`) escritos en `tsaservice.go`. `TSA_URL`, `TSA_USER` y `TSA_PASSWORD` se leían pero no se usaban. | Solo se usan `TSA_URL`, `TSA_USER`, `TSA_PASSWORD` (o `*_FILE`). Sin credenciales en el código ni valores por defecto. |
| La verificación terminaba antes de comprobar firma y cadena (`if true { return }`). | Verificación completa *fail closed*: si el sello no es válido, el registro no se completa ni se guarda nada. |
| Raíz descargada por HTTP; faltaba la intermedia, por lo que la cadena nunca validaba. | Raíz e intermedia de DigitelTS versionadas en el repositorio. Sin descarga por defecto. |
| Sin timeout ni nonce. | Timeout 30 s, nonce de 64 bits, sin reintentos, sin redirecciones. |
| `main.go` imprimía al arrancar toda la configuración (contraseñas SMTP/TSA, `MANAGEMENT_API_KEY`, token TMF, secretos de RPs) y se registraban el token de Postmark y la API key de gestión. | Volcado redactado (`[REDACTED]`) y test de regresión que impide pasar secretos a llamadas de log. |

Consecuencias:

1. **Rotar credenciales en Coolify no tiene efecto con la versión actual**: sigue usando las expuestas.
2. **Revocar las expuestas antes de desplegar esta versión deja sin sellado todos los onboardings** (DEV, PRE y PRO).
3. Tras la revocación, **no se puede volver a la imagen anterior** (ver §6).

Orden obligatorio: desplegar esta versión con credenciales nuevas en DEV → PRE → PRO, observar PRO, y **solo entonces** revocar las expuestas.

## 2. Decisiones previas con DigitelTS (bloquean PRO, no DEV)

| # | Pregunta | Por qué | Si no hay respuesta |
|---|----------|---------|--------------------|
| 1 | Endpoint RFC 3161 de **producción** | `timestamp-service.pre-api.digitelts.com` es, por nombre, preproducción. No se ha inventado ninguno. | No desplegar PRO con un endpoint no confirmado. |
| 2 | ¿Los sellos de `pre-api` son cualificados y están cubiertos por el contrato? | Todos los entornos, PRO incluido, han sellado contra `pre-api`. Los tokens revisados los firma `DIGITEL TS QUALIFIED TSU 01 G3 EDCSA`, que figura *granted* en la TSL española, pero debe confirmarlo el proveedor. | Registrar el riesgo para los contratos históricos de PRO. |
| 3 | ¿Devuelve el nonce? | RFC 3161 lo exige si se envía; esta versión lo exige. | Se comprueba en DEV (§4.4); en el peor caso `TSA_NONCE=false`. |
| 4 | Política OID de sus sellos | Los tokens actuales usan `0.4.0.2023.1.1`. | Dejar `TSA_POLICY_OID` sin definir. |
| 5 | Credenciales distintas por entorno | Hoy (Jira) son las mismas en DEV/PRE/PRO. | Usar las nuevas en los tres; pedir separación después. |
| 6 | Procedimiento y plazo de revocación de las expuestas | Necesario para §5. | — |

## 3. Variables de Coolify

Configurar como **variables de runtime** (no *build variables*: la imagen no debe contener secretos). `TSA_USER` y `TSA_PASSWORD` como secretas/bloqueadas. Valores en 1Password › Vault ISBE › "Credentials TSA (OnBoarding)".

| Variable | DEV | PRE | PRO | Secreta |
|----------|-----|-----|-----|---------|
| `PROFILE` | `isbe-dev` | `isbe-pre` | `isbe-pro` | no |
| `TSA_URL` | endpoint confirmado para DEV | endpoint confirmado para PRE | **endpoint de producción confirmado (§2.1)** | no |
| `TSA_USER` | nueva | nueva | nueva | sí |
| `TSA_PASSWORD` | nueva | nueva | nueva | sí |
| `TSA_CA_CERT_URL` | **eliminar** | **eliminar** | **eliminar** | no |
| `TSA_POLICY_OID` | `0.4.0.2023.1.1` si §2.4 está confirmado | ídem | ídem | no |
| `TSA_REVOCATION_CHECK` | `crl` (para probarlo) | `crl` | `crl` tras validarlo en DEV/PRE | no |

Notas:

* Alternativa a `TSA_PASSWORD`: montar un fichero (Storage de Coolify) y definir `TSA_PASSWORD_FILE=/ruta`. No se pueden definir ambas.
* Si se quiere conservar `TSA_CA_CERT_URL`, es obligatorio añadir
  `TSA_TRUST_ANCHOR_SHA256=011e258310b37f92030d14a672079507632cf72789fc101ce0a0bdc5ef2808cc`; sin ella el servidor no arranca.
* No hace falta ninguna otra variable TSA. `TSA_TIMEOUT`, `TSA_HASH_ALGORITHM` (SHA-512) y `TSA_NONCE` tienen valores por defecto adecuados.
* `SMTP_*`, `MANAGEMENT_API_KEY`, `ISBETMF_ADMIN_TOKEN` y `CERTAUTH_ADMIN_PASSWORD` no cambian, pero ya no aparecen en los logs.

## 4. Procedimiento por entorno (DEV → PRE → PRO)

No pasar al siguiente entorno hasta completar todas las comprobaciones del actual. PRO, además, requiere §2.1.

### 4.1 Antes

* Copia de seguridad del volumen `data/` (base de datos y contratos).
* Anotar la imagen desplegada actualmente (para §6 mientras las credenciales antiguas sigan activas).

### 4.2 Desplegar

Configurar las variables de §3 y desplegar.

### 4.3 Comprobar el arranque (logs de Coolify)

Deben aparecer:

```
TSA trust anchor loaded ... subject="...CN=DIGITEL TS CA ROOT 01..." sha256="011e2583...08cc"
TSA intermediate certificate loaded ... subject="...CN=DIGITEL TS QUALIFIED CA TSA G1..."
TSA service configured ... config.url="https://<host>/..." config.user_set=true config.password_set=true
```

En el volcado `Full config (secrets redacted)`, las claves `Password`, `ManagementAPIKey`, `TMFAdminToken` y `ClientSecret` deben mostrar `[REDACTED]`. **Si aparece cualquier secreto en claro, detener el despliegue.**

Si falta configuración, el contenedor no arranca y el error nombra la variable: `TSA_URL is required for profile ...`, `TSA user and password required ...`, `TSA_URL: HTTPS is required`, `TSA_CA_CERT_URL requires TSA_TRUST_ANCHOR_SHA256 ...`.

Después, `/health` debe responder `healthy` (no depende de la TSA).

### 4.4 Probar el servicio

1. **Sello real, una sola vez** (consume cuota), desde la terminal del contenedor en Coolify:
   ```bash
   /tsatool probe -confirm
   ```
   Esperado: `OK: timestamp token verified`, `signer: ... DIGITEL TS QUALIFIED TSU ...`, cadena de 3 certificados terminada en `DIGITEL TS CA ROOT 01` y `revocation: checked` si `TSA_REVOCATION_CHECK=crl`. Si falla, ver §6 y §7.
2. **Evidencias históricas** (solo lectura, sin llamar a la TSA):
   ```bash
   cd / && /tsatool verify-registration -db data/onboard.db -org <organization_identifier>
   ```
   Probar al menos con el registro más antiguo y con el más reciente del entorno.
3. **Onboarding completo de prueba** (DEV y PRE; en PRO solo si existe una organización de prueba acordada): debe completarse, y en los logs debe aparecer `TSA token verified` con el mismo `correlation_id` que el resto del flujo.
4. **Métricas** en `/metrics`: `tsa_requests_total{outcome="success"}` incrementado; `tsa_errors_total` y `tsa_verification_failures_total` sin incrementos inesperados.

### 4.5 Observación

* DEV y PRE: al menos un onboarding correcto.
* PRO: **24–48 h** (o el número acordado de onboardings reales) sin `tsa_errors_total` ni `tsa_verification_failures_total` antes de pasar a §5.

## 5. Revocación de las credenciales expuestas

Requisitos previos, todos cumplidos:

- [ ] DEV, PRE y PRO desplegados con esta versión y credenciales nuevas.
- [ ] §4.4 superado en los tres entornos y §4.5 en PRO.
- [ ] Ningún otro sistema (scripts, otros servicios, la máquina OVH) usa las credenciales expuestas.

Pasos:

1. Solicitar a DigitelTS la revocación de las credenciales expuestas.
2. Confirmar que la TSA las rechaza (criterio de aceptación de Jira) con una única petición, hecha **fuera** de los despliegues: por ejemplo `tsatool probe -confirm` en una máquina local, exportando las credenciales antiguas solo en esa sesión de terminal. Resultado esperado: `TSA rejected the credentials (HTTP 401)`.
3. Confirmar que los tres entornos siguen sellando (`tsa_requests_total{outcome="success"}`).
4. Registrarlo en ISBECORE-478.

## 6. Rollback

### Mientras las credenciales expuestas sigan activas (antes de §5)

Volver a la imagen anotada en §4.1. Funciona porque la versión anterior usa las credenciales del código, pero recupera todos los problemas: sellos sin verificar y credenciales y secretos en los logs. Es solo una medida temporal.

### Después de la revocación

**Volver a la imagen anterior deja el onboarding sin sellado**, porque esa versión usa las credenciales revocadas e ignora las variables. El rollback es siempre **hacia delante**, dentro de esta versión:

| Síntoma | Corrección sin desactivar la verificación |
|---------|-------------------------------------------|
| No arranca | Corregir la variable indicada en el error (§4.3). |
| `reason=auth` | Credenciales del entorno incorrectas; revisar 1Password y Coolify. |
| `reason=nonce` en todos los sellos | El proveedor no devuelve nonce: `TSA_NONCE=false` y abrir incidencia con DigitelTS. |
| `reason=policy` | Quitar `TSA_POLICY_OID` y confirmar la política con el proveedor. |
| `reason=revocation` (CRL inaccesible) | `TSA_REVOCATION_CHECK=none` temporalmente. |
| `reason=chain` tras una renovación de la CA del proveedor | Añadir la nueva intermedia o raíz (`TSA_INTERMEDIATES_FILE` / `TSA_TRUST_ANCHORS_FILE`), verificando su huella con el proveedor y la TSL. |
| Fallo de código en esta versión | Revertir el commit concreto y desplegar una versión corregida que mantenga la configuración por variables. |

No existe, deliberadamente, ninguna variable para desactivar la verificación criptográfica. Mientras se corrige, los onboardings fallan de forma controlada: no se guarda nada y el usuario puede reintentar más tarde. El cambio no modifica el esquema de la base de datos ni las evidencias existentes, así que ningún rollback requiere migraciones.

## 7. Diagnóstico desde los logs de Coolify

Filtrar por `component=tsa`. Cada operación tiene `op_id`, y los registros llevan `correlation_id` (el `auth_code` del flujo).

| Log / `reason` | Significado | Acción |
|----------------|-------------|--------|
| `TSA request failed reason=auth` (401/403) | Credenciales rechazadas | Revisar `TSA_USER`/`TSA_PASSWORD` |
| `reason=rate_limited` (429) | Cuota o límite | Contactar con DigitelTS |
| `reason=server_error` / `network` / `timeout` | Proveedor o red | Reintentar; revisar la salida a Internet |
| `reason=http_status` | Estado inesperado o redirección | Revisar `TSA_URL` |
| `TSA rejected the timestamp request` | PKIStatus de rechazo | Revisar algoritmo o política |
| `TSA token verification failed reason=...` | Token no conforme (ver §6) | No desactivar la verificación; escalar |

## 8. Rotaciones futuras

1. Pedir credenciales nuevas (una por entorno) y guardarlas en 1Password.
2. Actualizar Coolify y redesplegar entorno a entorno, repitiendo §4.3 y §4.4.1.
3. Revocar las anteriores (§5).

## 9. Historial de Git y otros secretos

Las credenciales TSA expuestas siguen en el historial público y deben darse por comprometidas: la **revocación** es lo que cierra el riesgo. No se ha reescrito el historial. Reescribirlo (`git filter-repo --replace-text`) obligaría a forzar el push de todas las ramas, invalidaría clones y forks, cambiaría los hashes referenciados en Jira y en las PRs, y no eliminaría las copias ya descargadas. Requiere aprobación aparte.

El historial contiene también una **contraseña SMTP** en `internal/email/email_test.go` (retirada en esta rama). Debe tratarse igual: confirmar si sigue activa y rotarla. Ticket aparte.

Recomendado (fuera del código): activar en GitHub *secret scanning* con *push protection*.
