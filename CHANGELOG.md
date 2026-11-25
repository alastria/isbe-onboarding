# Changelog

Todos los cambios relevantes de este proyecto se documentan en este fichero.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [Unreleased]

### Añadido

- Certificados organizativos no eIDAS aprobados en `approved_certificates` aceptados también en
  producción si cumplen la política de confianza del entorno (`MANUAL_APPROVAL_CA_FILE`): cadena
  hasta las CA del bundle, vigencia, uso de clave y revocación por CRL con fallo cerrado.

### Cambiado

- CertSec consulta la whitelist antes de exigir `organizationIdentifier` o `serialNumber`.
- La comprobación de CRL de la TSA pasa a `internal/crlcheck`, compartida con esa política.
- Para certificados sin nombre de persona, el representante legal se introduce en el formulario.
- Los certificados rechazados por CertSec muestran un mensaje claro (ES/EN) según el motivo en
  lugar del error interno.

### Seguridad

- Los pasos del alta y el endpoint de token exigen que CertAuth haya aceptado el certificado
  actual del proceso y, para emitir tokens, que el flujo haya terminado.
- El identificador de organización del contrato, TMF y gestión se toma siempre del certificado;
  un valor distinto en el formulario se rechaza.

## [1.0.0]

Primera versión etiquetada.
