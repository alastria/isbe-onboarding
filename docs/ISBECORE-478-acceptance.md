# ISBECORE-478 — Estado de los criterios de aceptación

Estado a 10/11/2026, rama `fix/isbecore-478-tsa-hardening` (PR #10), tras corregir las observaciones de la revisión. La petición real a DigitelTS con las credenciales nuevas **no se ha ejecutado todavía**.

**Verificado** = demostrado en esta rama con tests o comprobaciones reproducibles.
**Pendiente** = depende de DigitelTS, de Coolify o de una acción del equipo; no se puede verificar desde el código.

## Criterios de Jira (Gherkin)

| Criterio | Estado | Evidencia o dependencia |
|----------|--------|--------------------------|
| `tsaservice/tsaservice.go` no contiene usuario ni contraseña de la TSA como literal | **Verificado** | No queda ningún literal en el árbol de trabajo (`grep`). Arranque sin credenciales → error (`TestConfigureTSA`, `TestNewTSAServiceValidation`, prueba en Docker). Siguen en el **historial** (ver deployment §9). |
| Tras la rotación, la TSA rechaza las credenciales anteriores | **Pendiente (DigitelTS)** | El 06/11 ~10:04 UTC las credenciales expuestas **seguían aceptándose** (un test preexistente las usó en la línea base). Se comprueba en deployment §5.2, después de desplegar en los tres entornos. |
| DEV, PRE y PRO, con credenciales nuevas, sellan correctamente un onboarding | **Pendiente (Coolify y prueba real)** | Primero, una única petición real desde local: `TestTimestampAndVerify` (`-tags integration`, mismas comprobaciones que `TestAcceptanceHarnessAgainstMock`). Procedimiento en deployment §4. Del lado del código: el flujo completo está probado contra un TSA local (`TestCreateRegistrationStoresVerifiedEvidence`), y el verificador acepta tokens reales de DigitelTS (`TestRealDigitelTSTokenVerifies`, `tsatool verify-registration` sobre registros reales de DEV). |
| Un commit con un secreto es bloqueado por la CI o por GitHub | **Pendiente (infraestructura)** | Requiere activar *secret scanning* con *push protection* en GitHub. Como protección parcial en el código, `TestNoSecretsInLogCalls` impide registrar secretos de servicio. |

## Criterios técnicos de la tarea

| Criterio | Estado | Evidencia |
|----------|--------|-----------|
| Rama `fix/isbecore-478-tsa-hardening` basada en la rama de integración | **Verificado** | Basada en `origin/develop` actualizado (ver "Commits"). |
| No hay credenciales TSA reales en el código | **Verificado** | Ver arriba. También se ha retirado una contraseña SMTP de `internal/email/email_test.go`. |
| Las variables de entorno se usan realmente | **Verificado** | `TestTimestampSuccess` (cabecera Basic con las credenciales configuradas), `TestTimestampUsesConfiguredCredentials`, `TestApplyEnv`. |
| URL TSA configurable por entorno | **Verificado** | `TestConfigureTSA` (DEV/PRE/PRO independientes; `TSA_URL` obligatoria fuera de `local`), `TestTimestampSuccess` (se usa la ruta configurada). |
| Bypass de verificación eliminado | **Verificado** | `TestTamperedSignatureIsRejected`: firma alterada con imprint intacto → rechazo. |
| Validación criptográfica completa | **Verificado** | `TestMandatoryChecksMatrix`: 36 tokens, cada uno viola una única comprobación obligatoria, y todos se rechazan con el motivo esperado. `TestLegitimateVariantsAccepted`, `TestAlgorithms`, token real de DigitelTS. |
| Respuestas manipuladas rechazadas | **Verificado** | Matriz anterior, `TestTruncatedResponsesNeverVerify` (todos los prefijos y todos los bit flips), `FuzzVerify` y `FuzzVerifyRealToken` (token real mutado con trust store externo; 90 s cada uno sin pánicos ni aceptaciones con contenido distinto). |
| Mecanismo de confianza seguro | **Verificado** | Trust store embebido con procedencia documentada; descarga solo con huella fijada (`TestPinnedCADownload`); sin redirecciones. La intermedia `CA TSA G1` embebida se ofrece con cualquier fuente de anclas (fichero, PEM, URL fijada), solo si la emitió un ancla configurada y nunca como ancla: `TestRealTokenWithExternalTrustSources`, `TestEmbeddedIntermediateIsNeverAnAnchor`, `TestRealTokenVerificationIsOffline` (revisión PR #10). |
| Timeout y controles HTTP | **Verificado** | `TestTimestampTimeout`, `TestTimestampContextCancellation`, `TestTimestampResponseTooLarge`, `TestTimestampHTTPStatuses`, `TestTimestampDoesNotFollowRedirects`. |
| Nonce implementado y probado | **Verificado (código)** / **Pendiente (proveedor)** | `TestTimestampNonce` (ausente, incorrecto, respuesta reutilizada, único por petición, desactivado). Falta confirmar que DigitelTS lo devuelve (deployment §2.3). |
| No se almacenan evidencias sin validar | **Verificado** | `TestCreateRegistrationFailsClosed` (TSA caída, firma inválida, nonce ausente, rechazo) y `TestCreateRegistrationFailsClosedOnAuthAndTimeout` (401, timeout): no quedan ni fila ni fichero. |
| Compatibilidad histórica | **Verificado** | Formato de evidencia sin cambios (`TestTimestampedEvidenceFormatIsStable`); fila insertada como la guardaba la implementación anterior (SHA-512, sin nonce) verifica (`TestLegacyRegistrationEvidenceVerifies`); token real del 08/10 verifica con trust store embebido y externo; los dos registros reales de la BD de desarrollo verifican con `tsatool verify-registration`. Pendiente repetirlo sobre los datos de PRE y PRO (deployment §4.4.2). |
| Logs y métricas | **Verificado** | `TestTimestampNeverLogsSecrets`. Las métricas `tsa_*` se registraban en el registro por defecto y `/metrics` servía otro: corregido; `TestMetricsEndpointExposesTSAMetrics` consulta `/metrics` (revisión PR #10). `password_set` ya no aparece como `[REDACTED]` (`TestRedactedConfigJSONKeepsPresenceFlags`). |
| Ningún secreto en logs | **Verificado** | `TestRedactedConfigJSONHidesEverySecret` (todos los campos de la configuración por reflexión), `TestNoSecretsInLogCalls` (análisis del código fuente), `TestConfigRedaction`, arranque en Docker sin la contraseña en los logs. |
| Los tests unitarios no dependen de credenciales ni de red | **Verificado** | Suite completa ejecutada en un contenedor con `--network none`. Los tests de red (TSA, email, EU DSS) solo se compilan con `-tags integration`. |
| El proyecto compila y los tests relevantes pasan | **Verificado, con una excepción preexistente** | `go build`, `go vet` (con y sin tag) y `go test`/`-race` en verde, salvo `TestGetContract`, que entra en pánico en la librería PDF (`folio`) desde antes de esta rama. |
| Documentación actualizada | **Verificado** | README, DOCKER_SETUP, PROJECT_DOCUMENTATION, `.env.example`, `tsaservice/README.md`, esta carpeta `docs/`. |
| Procedimiento de rotación y despliegue en Coolify | **Verificado (documento)** | [ISBECORE-478-deployment.md](ISBECORE-478-deployment.md). Su ejecución está pendiente. |
| Sello cualificado eIDAS | **No afirmado** | Se verifica la validez criptográfica. La condición de cualificado depende de la TSL a la fecha del sello y de la confirmación del proveedor (deployment §2.2). |

## Hallazgos fuera del alcance (tickets aparte)

| Hallazgo | Severidad | Notas |
|----------|-----------|-------|
| Contraseña SMTP en el historial público (`internal/email/email_test.go`) | Alta | Retirada en esta rama; confirmar si sigue activa y rotarla. |
| Secretos de configuración en el código (`MANAGEMENT_API_KEY` de `local`, `ISBETMF_ADMIN_TOKEN` de `local`, `ClientSecret` literal de los RPs predefinidos) | Alta | Relacionado con ISBECORE-464. Ya no se imprimen en los logs. |
| `getContract` escribe `contract.html`, con datos del contrato, en el directorio de trabajo en cada generación | Media | Datos personales persistidos innecesariamente (en el contenedor, `/contract.html`). |
| Se registran en debug tokens de usuario (ID/Access token, `code_verifier`, `vp_token`) | Media | `certauthserver/oidc_handlers.go`, `wallet_handlers.go`. El nivel de log por defecto es Debug. |
| `TestGetContract` entra en pánico (`folio`: fuente nula) | Baja | Ya ocurría antes de esta rama; aborta el resto de tests del paquete si no se excluye. |
| Formato de evidencia sin delimitar ni versionar | Media-baja | Documentado en `tsaservice/README.md`. Necesita una migración con una columna de versión. |
| Revisar otros repositorios públicos de la organización con el mismo patrón | — | Propuesta 6 de Jira. |
