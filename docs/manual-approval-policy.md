# Certificados no eIDAS aprobados manualmente

La whitelist `approved_certificates` (PR #5) asocia la huella SHA-256 del DER de un certificado
con un `organizationIdentifier` aprobado. Este cambio permite que la usen también certificados
organizativos de autenticación de cliente **no cualificados** (sin `organizationIdentifier` ni
`serialNumber` en el Subject, sin QCStatements), incluido en producción, sin cambiar el esquema.

## 1. Funcionamiento

**CertSec** consulta la whitelist antes de exigir `organizationIdentifier` o `serialNumber`: un
certificado sin ninguno de los dos solo pasa si su huella está aprobada. La autenticación de
administración no consulta la whitelist: un certificado aprobado nunca obtiene privilegios.

**CertAuth** (`certauthserver/trust_policy.go`) decide en `/certificate-back`:

| Orden | Política | Condición | Resultado |
|---|---|---|---|
| 1 | eIDAS (sin cambios) | EU DSS `PASSED` | `EIDASCertificate = true`; única vía para marcarlo como eIDAS |
| 2 | Aprobación manual | Sin `organizationIdentifier` propio, huella aprobada para ese identificador (se vuelve a consultar la base de datos) y cumple la política del §2 | Aceptado, pantalla "Certificado aprobado manualmente", `EIDASCertificate = false` |
| 2' | Aprobado que incumple la política, o política sin configurar en `isbe-pro` | — | Rechazado |
| 3 | Resto | — | Comportamiento anterior: `isbe-pro` rechaza; DEV/PRE aceptan en modo prueba |

Si el certificado no tiene nombre de persona, el formulario pide el nombre del representante.
Cuando CertSec rechaza un certificado (no aprobado, no vigente o ilegible), el usuario ve un
mensaje claro en español o inglés; el error interno solo va al log.

**Flujo ligado al certificado aceptado.** CertAuth guarda la huella del certificado aceptado en el
proceso de autenticación. Email, verificación, contrato y aceptación exigen que coincida con el
certificado actual; el endpoint de token exige además que el flujo haya terminado (registro,
organización ya registrada o SSO). CertSec borra la marca al recibir otro certificado. El
identificador de organización del contrato, TMF y gestión sale siempre del certificado (o de su
aprobación): si el formulario envía otro `organization_nif`, se responde 400.

## 2. Política de confianza (`internal/certpolicy`)

| Garantía | Quién | Cómo |
|---|---|---|
| Posesión de la clave privada | Proxy mTLS | Handshake TLS (`CertificateVerify`) |
| Cabecera no falsificable | Proxy y red | §4 |
| Cadena y emisor | Aplicación | `x509.Verify` hasta una raíz autofirmada del bundle, solo con las intermedias del bundle (nunca las del cliente ni el almacén del sistema): solo las CA listadas pueden emitir |
| Vigencia | Aplicación | De toda la cadena |
| Uso de clave | Aplicación | No CA, KU `digitalSignature`, EKU `clientAuth`, RSA ≥ 2048 o ECDSA P-256/384/521 |
| Revocación | Aplicación | CRL de cada certificado salvo la raíz (incluidas las intermedias), con `internal/crlcheck` (el mismo código que la TSA): firma del emisor, `thisUpdate`/`nextUpdate`, 10 s, 10 MB, sin redirecciones, caché ≤ 15 min. Si no se puede determinar, se rechaza ("pruebe más tarde") |
| Huella exacta | Aplicación | SHA-256 del DER en CertSec y otra vez en CertAuth |
| Asociación con la organización | Operación | Alta manual tras verificar identidad y representación |

Las URL de CRL solo se consultan para certificados aprobados cuya cadena ya llega a una CA del
bundle.

## 3. Configuración

| Variable | Valor |
|---|---|
| `MANUAL_APPROVAL_CA_FILE` | PEM con la raíz y la intermedia emisora de los certificados aprobados. Sin definir: política desactivada. El servidor no arranca si el fichero no contiene al menos una raíz autofirmada o contiene algo que no es una CA. |

Al arrancar se registra cada CA (`Manual approval CA role=... subject=... sha256=...`). El
fichero se monta por entorno (solo lectura); no va en la imagen ni en el repositorio. El
contenedor necesita salida HTTP hacia los CRL Distribution Points de la cadena (respeta
`HTTP_PROXY`). **La CA de laboratorio nunca se configura en PRO.**

## 4. Frontera de confianza con el proxy (requisito previo a PRO)

CertSec confía en la cabecera `tls-client-certificate` (o `X-Amzn-Mtls-Clientcert`). Antes de
activar la política en un entorno hay que comprobar, y dejar constancia, de que:

1. el proxy termina mTLS para `certsec.<entorno>` y exige certificado de cliente;
2. el proxy **sobrescribe** la cabecera en cada petición (`header_up tls-client-certificate ...`
   en Caddy) y elimina la otra;
3. el puerto de CertSec (8011) no es accesible sin pasar por el proxy;
4. si el proxy limita las CA de cliente aceptadas, incluye la del certificado aprobado.

Comprobación: una conexión sin certificado de cliente debe fallar en el handshake, y una cabecera
enviada por el cliente nunca debe llegar a CertSec.

## 5. Pruebas en DEV y PRE

1. **Bundle:** raíz + intermedia emisora en un PEM, montado en el contenedor y
   `MANUAL_APPROVAL_CA_FILE=/config/manual-approval/ca-bundle.pem`. Verificar las huellas de la
   raíz por un canal independiente. Para certificados de laboratorio, la raíz e intermedia del
   laboratorio (nunca en PRO).
2. **CRL:** desde el contenedor deben ser accesibles las URL de CRL del certificado y de la
   intermedia (`wget -qO- <url> | wc -c`). Para un laboratorio, sus URL deben resolver desde el
   contenedor (por ejemplo, un servicio estático en la red interna que sirva solo los CRL y
   certificados públicos).
3. **Whitelist** (copia de seguridad antes):

   ```sql
   INSERT INTO approved_certificates (certificate_sha256, organization_identifier, comment)
   VALUES ('<sha256 del DER en minúsculas>', '<identificador aprobado>', 'CS-407 <verificador> <fecha>');
   ```

   Huella: `openssl x509 -in cert.pem -outform DER | shasum -a 256`.
4. **Casos y logs esperados:**

   | Caso | Resultado | Log |
   |---|---|---|
   | Aprobado y válido | "Certificado aprobado manualmente", alta completa | `Using approved organization identifier`; `Certificate accepted ... trust_policy=manual_approval` |
   | No aprobado sin atributos | "No podemos aceptar este certificado" | `Certificate rejected by CertSec ... has not been approved` |
   | Caducado | "Certificado no vigente" | `Certificate rejected by CertSec ... Certificate expired` |
   | Revocado | "no cumple la política" | `Certificate rejected ... manual_policy_error="certificate is revoked: ..."` |
   | CRL inaccesible | "pruebe más tarde" | `... revocation status could not be determined ...` |
   | `organization_nif` alterado | HTTP 400 | `Invalid contract form` |
   | eIDAS habitual y segundo login | Sin cambios | `trust_policy=eidas` |

5. **Limpieza:** `DELETE FROM approved_certificates WHERE certificate_sha256 = '<huella>';`, y los
   registros, organizaciones en TMF/gestión y usuarios de prueba creados.

## 6. Checklist de PRO

- [ ] §4 verificado y documentado para el proxy de PRO.
- [ ] Bundle con la raíz y la intermedia aprobadas; el arranque muestra exactamente esas huellas.
- [ ] Salida HTTP del contenedor hacia los CRL Distribution Points de la cadena.
- [ ] Identidad y poderes de representación verificados; fila en `approved_certificates`.
- [ ] Certificados eIDAS habituales y segundo login siguen funcionando en PRE.
- [ ] Autenticación de aceptación del titular en PRE y en PRO: `trust_policy=manual_approval` e
      identificador correcto en registro, TMF, gestión y token.

## 7. Rollback

- Desactivar: quitar `MANUAL_APPROVAL_CA_FILE` y reiniciar. PRO vuelve a rechazar los aprobados no eIDAS.
- Retirar una aprobación: borrar su fila. Efecto en el siguiente login; las sesiones SSO abiertas
  (en memoria, 24 h) se invalidan reiniciando el servicio. Los tokens emitidos valen hasta caducar.
- Imagen anterior: sin cambios de esquema; las filas de la whitelist son inofensivas.
