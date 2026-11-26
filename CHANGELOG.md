# Changelog

Todos los cambios relevantes de este proyecto se documentan en este fichero.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [Unreleased]

### Añadido

- Aprobación manual de certificados (CS-407): con `MANUAL_CERTIFICATE_APPROVAL_ENABLED=true`, los
  certificados de `approved_certificates` se aceptan para la organización aprobada como alternativa
  a la validación eIDAS, sin consultar EU DSS. Nunca se marcan como eIDAS. Deshabilitada por defecto.
- `CLIENT_CERT_HEADER`: única cabecera de la que se lee el certificado de cliente, obligatoria con
  la aprobación manual.
- El formulario del contrato pide el nombre del representante cuando el certificado no lo incluye.

### Cambiado

- Los pasos posteriores del flujo y la emisión de tokens exigen que CertAuth haya aceptado el
  certificado y que el flujo haya terminado.
- El identificador de organización del contrato procede siempre del certificado (o de su aprobación).
- Al retirar una aprobación, la sesión SSO del certificado deja de reutilizarse.

## [1.0.0]

Primera versión etiquetada.
