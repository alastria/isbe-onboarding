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
- `approved_certificates` admite `serial_number`, `given_name` y `surname` opcionales, verificados por
  ISBE en la aprobación. Solo completan los atributos que le faltan al certificado, tal como se
  introducen, y permiten emitir `user_identifier` y el nombre del representante en los tokens. Un
  valor distinto del que trae el certificado rechaza la aprobación, y cambiarlos invalida los procesos
  y sesiones SSO que usaban los anteriores.

### Cambiado

- **Cambio incompatible:** el certificado de cliente se lee solo de la cabecera
  `tls-client-certificate`. Ya no se lee `X-Amzn-Mtls-Clientcert`: un despliegue cuyo proxy solo
  envíe esa cabecera deja de autenticar certificados (también en administración) hasta que el
  proxy envíe el certificado en `tls-client-certificate`.
- Los pasos posteriores del flujo y la emisión de tokens exigen que CertAuth haya aceptado el
  certificado y que el flujo haya terminado.
- El identificador de organización del contrato procede siempre del certificado (o de su aprobación).
- Al retirar una aprobación o caducar el certificado, su sesión SSO deja de reutilizarse y los
  procesos de autenticación abiertos no pueden continuar ni obtener tokens.
- Un certificado sin `organizationIdentifier` ni `serialNumber` y sin aprobación manual muestra el
  mensaje «Certificado no autorizado» (también en inglés); el detalle técnico queda en los logs.

## [1.0.0]

Primera versión etiquetada.
