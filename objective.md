# Objectives of the project

This project is intended to be a minimalist OpenID Provider (OP) focused on only one thing: application (Relying Partie or RP) use it to delegate authentication of users which have an eIDAS certificate issued to them by a QTSP (Qualified Trust Service Provider). This project does not have to provide all the features that "normal" OPs provide. The subset required by this project is described below.

The overall flow is the following. There are several actors:

- The application, acting as a RP. When the application wants to authenticate a user, it uses the OIDC Authentication Code Flow to pass control to the CertAuth server, acting as an OpenID Provider (OP). The OP runs in a domain of its own (e.g. certauth.mycredential.eu).
- The OP presents a screen to the user, describing what is going to happen, and allowing the user to click a button to rrequest the eIDAS certificate from the browser. It asks for consent to the user.
- The button above redirects the user to another domain (eg. certsec.mycredential.eu). This domain is configured in the reverse proxy (we use Caddy, but it is the same for Nginx) to ask for a client certificate.

For example, in Caddy it is done with:

```
(client_auth) {
    tls {
        client_auth {
            mode require
        }
    }
}
```

- When the user's browser starts the TLS session, it presents a popup to the user to select one of the certificates in the keystore of the user machine. It even allows the user to use a smartcard or any other supported mechanism in the client machine.

- The user selects the certificate to be used (we require an eIDAS certificate, more on this later), and the browser starts the TLS session. The reverse proxy then sends the certificate to our server (at the internal port assigned to the domain certsec.mycredential.eu). In Caddy, this is done with:

```
certsec.mycredential.es {
    import client_auth
    reverse_proxy localhost:8090 {
        header_up tls-client-certificate {http.request.tls.client.certificate_der_base64}
    }   
}
```

- We have configured Caddy to send the certificate in the `tls-client-certificate` HTTP header.
- Our application receives the certificate, decodes it and extracts the user information from the certificate, mainly the Subject field.
- For this application, we require the certificate to be an "organizational" certificate, that is, either a certificate for seals (QSeal), or a certificate of representation (a QSign where the user is associated to the organization that represents). In both certificates, the Subject field contains the `organizationIdentifier` (OID 2.5.4.97). For details, see the `x509util` package in this project.
- Once this is done, the certsec.mycredential.eu server sends back to the certauth.mycredential.eu server the information about the user (essentially the fields in the Subject field of the certificate).
- The certauth server then responds back to the RP using the standard OIDC mechanism (specifically Authentication Code Flow). The user information is in the ID Token, as usual, using the standard claims when appropriate, but with claims defined to suit our needs if there are no standard claims.
- The RP then uses that information to welcome the user or whatever the application requires. The RP can also request an access token from the OP. In our simple OP, we will not support token refresh.

NOTE: Why we need two domains for the OP. The essential reason is because I have not found a proper mechanism to control (with standard Go) the TLS session stablishment. If there is a mechansm to avoid having two domains, I would like to implement that. The main reason is that as soon as the user is redirected to a domain configured in the reverse proxy to ask for a client certificate, the user is going to see the popup from the browser. I do not know of any way to control that from JavaScript or from the server. We need to present an initial logon screen telling the user what is going to happen and a button. And I dont want the application to do that.

NOTE 2: There is another thing that I dont know how to do in Go. Once a user has selected a certificate, the browser (eg. Chrome) caches the certificate, so it is not possible to ask from the server for a different certificate. Only closing ALL browser windows (it is not enough closing the current window) and restarting the server, the user can selec a different certificate. This means that we can not implement a "logout" feature just for the certificate. We need a session which can be expired or revoked.

## Additional considerations

We need to build a production-grade server, minimalistic but robust and simple to understand and maintain. Maintainability is one of the most important attributes that we must achieve. In the future, it must be easy for people not involved in development to understand the code and maintain or evolve it.

The current codebase is far from finished. We will build the server from scratch. The current codebase has some pieces of code and structure which can be used as inspiration, but there are no limits to change anything if needed.

### Implementation of basic OP functionality

In the current code, I am using code based on code from [ORY Fosite example](https://github.com/ory/fosite-example) for the OpenID Provider functionality. The code maintains the copyright and attributions, but it removes unneccesary code to help keep this server simple and understandable.

If there are other options (including writing the required functionality from scratch), I want to consider them.

### An example RP

The codebase must include a simple example RP with some screens to allow the user to see the whole flow. It should be isolated to its own package, to not mess with the OP code.

### Server framework to use

The framework must be Fiber, but the Fiber-dependent things must be isolated as soon as possible and most of the code must be framework-independent. Switching from Fiber to Echo should be as easy as possible, with the minimium lines of code written. Another way to put it is: imagine that we implement the OP both in Fiber and Echo. Both implementations must share the maximum amount of code possible. One possible strategy that has worked for me in the past is to convert in the handlers the HTTP request to an independent representation as a struct, which is then the one used elsewhere. In most cases, we only need a few fields of the "real" http request. And something similar for the reply. An example of this strategy can be seen in https://github.com/hesusruiz/isbetmf/tree/main/tmfserver/handler/fiber

We need to serve two ports, so they will be assigned to the two different domains.

### Communication between the actors

The communication between the RP and the server ate certauth.mycredential.eu must be with standard OIDC (Auth Code Flow).

The communication between certauth.mycredential.eu and certsec.mycredential.eu can be by whatever mechanism we want to implement. Both are running in the same process, so we can implement whatever mechanism we want. But they have both screens, so we may use redirection via the browser, if we consider this secure enough. I would favor a redirection to pass control, but with actual used data being passed in the backchannel (standard or adhoc).

### Implementation of user screens

I favor to use Go templates (probably with the standard utility in Fiber). But I am open to consider other alternatives. Client-side frameworks like React or Angular are out of the question, following the minimalistic principles. No Node-based tools are allowed. The screens must be as close to plain HTM/CSS as possible. Tools to help are possible, but not full-fledged frameworks which need frontend building.

I can consider other templting system than the standard Go one, but I do not want Go-based systems where you need Go skills to design the screens.

### Registration of RPs in the server

The server needs to have RPs registered, so it is not open to anyone. However, the OP does not need high security authentication of the RPs, because the OP does not have any user information and will never register user information. This is not a standard OP. The user information is in the eIDAS certificate presented by the user, and the OP is just a technical mechanism to simplify authentication to RPs. What I mean is that we need a very basic mechanism for registration of RPs, for example the origin URL and redirection URL. Of course, in our screen to the user, we have to present very clearly what is the domain that is asking for the certificate.

### Database to use

We need a simple, robust, high performance, simple to operate, production grade database. This is SQLite, which for this application is better than networked databases like PostgeSQL or MySQL. We do not expect more than 10.000 transactions per second, so a modest server is more than enough in terms of performance. We will never reach the performance limit of SQLite, and if we do find it, the system is easy to scale horizontally.e will cross that bridge when it is needed (never, most probably).

We do not care in this codebase about high-availability and disaster recovery, because they are very easy to achieve with SQLite for applications like this one.

In any case, the database layer should be pluggable, so people with mental problems and low self-confidence can replace SQLite with another one if they want.

