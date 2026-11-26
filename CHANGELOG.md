# Changelog

Todos los cambios relevantes de este proyecto se documentan en este fichero.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [Unreleased]

### Añadido

- Aprobación manual de certificados (CS-407): los certificados de `approved_certificates` se aceptan
  para la organización aprobada como alternativa a la validación eIDAS, sin consultar EU DSS, en
  todos los perfiles. Nunca se marcan como eIDAS. Antes de desplegar hay que revisar y volver a
  aprobar las filas existentes de `approved_certificates` (ver README).
- El formulario del contrato pide el nombre del representante cuando el certificado no lo incluye.

### Cambiado

- El certificado de cliente se lee solo de la cabecera `tls-client-certificate`, sin alternativa.
- Los pasos posteriores del flujo y la emisión de tokens exigen que CertAuth haya aceptado el
  certificado y que el flujo haya terminado.
- El identificador de organización del contrato procede siempre del certificado (o de su aprobación).
- Al retirar una aprobación o caducar el certificado, su sesión SSO deja de reutilizarse y los
  procesos de autenticación abiertos no pueden continuar ni obtener tokens.

## [1.0.0]

Primera versión etiquetada.
