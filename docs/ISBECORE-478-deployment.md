# ISBECORE-478 — Despliegue del endurecimiento de la integración TSA

Guía para el operador de Coolify tras el merge de `fix/isbecore-478-tsa-hardening`.
Detalle técnico: [tsaservice/README.md](../tsaservice/README.md).

## 1. Qué cambia en tiempo de ejecución

| Antes | Después |
|-------|---------|
| El código usaba **siempre** el usuario, la contraseña y la URL escritos en `tsaservice.go` (`pre-api` de DigitelTS). `TSA_URL`, `TSA_USER` y `TSA_PASSWORD` se leían pero **no se usaban** al sellar. | Se usan exclusivamente `TSA_URL`, `TSA_USER`, `TSA_PASSWORD` (o `*_FILE`). No hay credenciales en el código ni valores por defecto. |
| La verificación del sello terminaba antes de comprobar firma y cadena (`if true { return }`). | Verificación completa y *fail closed*; un sello no válido impide completar el registro. |
| La raíz de DigitelTS se descargaba por HTTP al arrancar; faltaba la intermedia, por eso la cadena nunca validaba. | Raíz e intermedia de DigitelTS versionadas en el repositorio (públicas, sin secretos). Sin descarga por defecto. |
| Sin timeout, sin nonce. | Timeout 30 s, nonce de 64 bits, sin reintentos, sin seguir redirecciones. |

**Consecuencia para la rotación**: con la versión desplegada actualmente, cambiar las credenciales en Coolify **no tiene ningún efecto**, y revocar las credenciales expuestas **rompe todos los onboardings** (el código sigue usando las antiguas). El orden correcto es: desplegar esta versión con las credenciales nuevas en DEV → PRE → PRO y, solo después, pedir a DigitelTS la revocación de las antiguas.

## 2. Variables en Coolify (por entorno)

Obligatorias en `isbe-dev`, `isbe-pre` e `isbe-pro`:

| Variable | Valor | Secreto |
|----------|-------|---------|
| `PROFILE` | `isbe-dev` / `isbe-pre` / `isbe-pro` | no |
| `TSA_URL` | Endpoint RFC 3161 **confirmado con DigitelTS para ese entorno** (HTTPS) | no |
| `TSA_USER` | Usuario nuevo (1Password › Vault ISBE › "Credentials TSA (OnBoarding)") | sí |
| `TSA_PASSWORD` | Contraseña nueva (ídem) | sí |

Marcar `TSA_USER` y `TSA_PASSWORD` como variables secretas/bloqueadas en Coolify y como *runtime only* (no *build variable*): la imagen no debe contenerlas. Alternativa: montar un fichero (Storage de Coolify) y usar `TSA_PASSWORD_FILE=/ruta/al/fichero` en lugar de `TSA_PASSWORD` (no se pueden definir ambas).

Revisar y **eliminar o completar** `TSA_CA_CERT_URL` si existe: ahora exige `TSA_TRUST_ANCHOR_SHA256`. Lo recomendado es eliminarla y usar el trust store embebido. Si se mantiene:

```
TSA_TRUST_ANCHOR_SHA256=011e258310b37f92030d14a672079507632cf72789fc101ce0a0bdc5ef2808cc
```

Opcionales (dejar sin definir salvo decisión explícita): `TSA_POLICY_OID` (recomendado `0.4.0.2023.1.1` tras confirmarlo con DigitelTS), `TSA_REVOCATION_CHECK=crl` (recomendado en PRO tras probarlo en DEV), `TSA_TIMEOUT`, `TSA_HASH_ALGORITHM` (mantener `sha512`), `TSA_NONCE`.

## 3. Pendiente de confirmar con DigitelTS antes de PRO

1. Endpoint de producción. `timestamp-service.pre-api.digitelts.com` es, por su nombre, de preproducción. No se ha inventado ningún endpoint de producción: debe facilitarlo el proveedor.
2. Si los sellos emitidos por `pre-api` tienen valor cualificado y están cubiertos por el contrato. Los tokens de prueba revisados (08/10/2026) los firma `DIGITEL TS QUALIFIED TSU 01 G3 EDCSA`, que figura como servicio QTST *granted* en la TSL española; aun así, el proveedor debe confirmarlo, porque **todos los entornos, PRO incluido, han sellado contra `pre-api` hasta ahora**, con independencia de `TSA_URL`.
3. Que acepta nonce (RFC 3161 lo exige si se envía). Si no, `TSA_NONCE=false` en ese entorno.
4. Política OID aplicable (`0.4.0.2023.1.1` en los tokens actuales) y algoritmo (SHA-512 aceptado hoy).
5. Si las credenciales nuevas son distintas por entorno (Jira indica que hoy son las mismas en DEV, PRE y PRO). Recomendado: una credencial por entorno.
6. Confirmación de la revocación de las credenciales expuestas.

## 4. Despliegue paso a paso

Para cada entorno, en orden **DEV → PRE → PRO**, sin pasar al siguiente hasta completar el anterior:

1. Configurar las variables del apartado 2 con las credenciales **nuevas**.
2. Desplegar la versión de la rama.
3. Comprobar el arranque en los logs de Coolify:
   - `TSA trust anchor loaded subject=...DIGITEL TS CA ROOT 01... sha256=011e2583...`
   - `TSA intermediate certificate loaded subject=...DIGITEL TS QUALIFIED CA TSA G1...`
   - `TSA service configured config.url=https://<host>/... config.user_set=true config.password_set=true`
   - Si falta algo, el servidor no arranca y el error indica la variable (`TSA_URL is required for profile ...`, `TSA user and password required`, `TSA_CA_CERT_URL requires TSA_TRUST_ANCHOR_SHA256`...).
4. Comprobar `/health` (no depende de la TSA).
5. Probar la conexión real **una sola vez** (consume un sello), desde la terminal del contenedor en Coolify (hereda las variables del servicio):
   ```bash
   /tsatool probe -confirm
   ```
   o completar un onboarding de prueba. Buscar en los logs `TSA token verified` con `signer=...` y `gen_time=...`.
6. Verificar que las evidencias ya almacenadas siguen siendo verificables (solo lectura, sin llamar a la TSA):
   ```bash
   cd / && /tsatool verify-registration -db data/onboard.db -org <organization_identifier>
   ```
   (desde `/`, porque `contract_document` guarda rutas relativas `data/contracts/...`; la base de datos se abre en solo lectura).
7. Revisar las métricas `tsa_requests_total`, `tsa_errors_total` y `tsa_verification_failures_total` en `/metrics`.

Cuando PRO funcione con las credenciales nuevas: solicitar a DigitelTS la revocación de las expuestas y comprobar que la TSA las rechaza (criterio de aceptación de Jira), sin usar la cuenta de PRO para la prueba si se puede evitar.

## 5. Diagnóstico desde los logs de Coolify

Filtrar por `component=tsa`. Cada operación tiene `op_id`; los registros llevan `correlation_id` (el `auth_code` del flujo).

| Log / razón | Significado | Acción |
|-------------|-------------|--------|
| `TSA request failed reason=auth http_status=401/403` | Credenciales rechazadas | Revisar `TSA_USER`/`TSA_PASSWORD` del entorno |
| `reason=rate_limited` (429) | Cuota o límite del proveedor | Contactar con DigitelTS |
| `reason=server_error` (5xx), `network`, `timeout` | Proveedor caído o red | Reintentar más tarde; revisar conectividad saliente |
| `reason=http_status` | Estado inesperado, incluida una redirección | Revisar `TSA_URL` |
| `TSA rejected the timestamp request` | PKIStatus de rechazo (p. ej. algoritmo o política no admitidos) | Revisar `TSA_HASH_ALGORITHM`/`TSA_POLICY_OID` |
| `TSA token verification failed reason=chain` | La TSU no encadena con el trust store | ¿Renovación de la CA de DigitelTS? Añadir la nueva intermedia con `TSA_INTERMEDIATES_FILE` |
| `reason=nonce` | Respuesta sin nonce o con otro nonce | Confirmar soporte de nonce; posible respuesta reutilizada |
| `reason=policy` / `algorithm` / `eku` / `ess` / `signature` / `imprint` | Token no conforme o manipulado | No desactivar la verificación; escalar a seguridad/proveedor |
| `reason=revocation` | CRL inaccesible o certificado revocado (solo con `crl`) | Comprobar acceso a `crl1.pki.digitelts.es` |

## 6. Rollback

Volver a la imagen anterior **solo mientras las credenciales expuestas sigan activas**: esa versión ignora las variables y usa las credenciales del código. Tras la revocación, el rollback deja el onboarding sin sellado. En ese caso, corregir la configuración y volver a desplegar esta versión. El cambio no modifica el esquema de la base de datos ni las evidencias existentes, por lo que el rollback no requiere migraciones.

## 7. Rotación futura de credenciales

1. Pedir credenciales nuevas a DigitelTS (una por entorno) y guardarlas en 1Password.
2. Actualizar `TSA_USER`/`TSA_PASSWORD` en Coolify y redesplegar, entorno a entorno, comprobando el paso 4.5.
3. Revocar las anteriores y comprobar que se rechazan.

## 8. Historial de Git

Las credenciales siguen en el historial público y deben darse por comprometidas: la **rotación y revocación** es lo que cierra el riesgo. No se ha reescrito el historial. Reescribirlo (p. ej. `git filter-repo --replace-text`) obligaría a forzar el push de todas las ramas, invalidaría los clones y forks existentes, cambiaría los hashes de los commits referenciados en Jira y PRs, y no eliminaría las copias ya descargadas; requiere aprobación aparte. Se recomienda además activar en GitHub el *secret scanning* con *push protection* (criterio de aceptación de Jira, fuera del alcance del código de esta rama).
