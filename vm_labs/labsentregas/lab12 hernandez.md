# Lab 12 — Operation VELVET LOCK

## TLS Hardening: Securing the Web with OpenSSL and Apache

| Field       | Value                          |
| ----------- | ------------------------------ |
| **Student** | Juan Limberg Hernandez del Rio |
| **Date**    | 2026-05-05                     |
| **OS**      | Ubuntu 22.04 (Vagrant VM)      |

---

## Part 1: HTTP Plaintext Capture — The Vulnerability

### 1.1 tcpdump Output (HTTP on port 80)

```
vagrant@svoboda:~$ sudo tcpdump -i lo -A -s 0 'port 80'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
22:12:41.507958 IP localhost.34772 > localhost.http: Flags [S], seq 278021018, win 65495, options [mss 65495,sackOK,TS val 3132593126 ecr 0,nop,wscale 6], length 0
E..<..@.@..............P..C..........0.........
............
22:12:41.507971 IP localhost.http > localhost.34772: Flags [S.], seq 3225145352, ack 278021019, win 65483, options [mss 65495,sackOK,TS val 3132593126 ecr 3132593126,nop,wscale 6], length 0
E..<..@.@.<..........P...;....C......0.........
............
22:12:41.507981 IP localhost.34772 > localhost.http: Flags [.], ack 1, win 1024, options [nop,nop,TS val 3132593126 ecr 3132593126], length 0
E..4..@.@..............P..C..;. .....(.....
........
22:12:41.508012 IP localhost.34772 > localhost.http: Flags [P.], seq 1:134, ack 1, win 1024, options [nop,nop,TS val 3132593126 ecr 3132593126], length 133: HTTP: GET /contacts.html HTTP/1.1
E.....@.@..Y...........P..C..;. ...........
........GET /contacts.html HTTP/1.1
Host: localhost
User-Agent: curl/7.81.0
Accept: */*
Authorization: Basic c3Zvb29kYTpzZWNyZXQxMjM=
22:12:41.508022 IP localhost.http > localhost.34772: Flags [.], ack 134, win 1022, options [nop,nop,TS val 3132593126 ecr 3132593126], length 0
22:12:41.508261 IP localhost.http > localhost.34772: Flags [P.], seq 1:654, ack 134, win 1024, options [nop,nop,TS val 3132593127 ecr 3132593126], length 653: HTTP: HTTP/1.1 200 OK
E...xC@.@............P...;.     ..D ...........
........HTTP/1.1 200 OK
Date: Tue, 05 May 2026 22:12:41 GMT
Server: Apache/2.4.52 (Ubuntu)
Last-Modified: Tue, 05 May 2026 21:59:51 GMT
ETag: "191-651192aa49aa8"
Accept-Ranges: bytes
Content-Length: 401
Vary: Accept-Encoding
Content-Type: text/html
<!DOCTYPE html>
<html>
<head><title>SVOBODA ... Source Registry</title></head>
<body style="font-family:monospace;background:#111;color:#0f0;padding:40px;">
  <h2>Source Registry ... CLASSIFIED</h2>
  <ul>
    <li>Source ATLAS ... Embassy contact, Bratislava</li>
    <li>Source WRAITH ... Ministry insider, Warsaw</li>
    <li>Source FALCON ... Border intelligence, Lviv</li>
  </ul>
</body>
</html>
```

### 1.2 Credential Decoded

**Command:**

```bash
echo "c3Zvb29kYTpzZWNyZXQxMjM=" | base64 -d
```

**Output:**

```
svoooda:secret123
```

**Username:** `svoooda`  
**Password:** `secret123`

### 1.3 Interceptor Analysis

**URL accessed:** `http://localhost/contacts.html`  
**Credentials exposed:** `svoooda:secret123`  
**Other exposed data:** `Host`, `User-Agent`, `Accept`, `Content-Type`, `Server` version (Apache/2.4.52), full HTML body with classified source list (ATLAS, WRAITH, FALCON).

**Security impact:** An interceptor capturing this traffic would immediately obtain valid credentials for the SVOBODA portal in plaintext — no decryption needed. With those credentials, the attacker could authenticate as the operative, access any protected resource on the server, and enumerate all active sources and their locations. Additionally, the server version exposed in the `Server` header allows targeted exploitation of known Apache vulnerabilities.

---

## Part 2: Generating the Cryptographic Key & Certificate

### 2.1 RSA Private Key Generation

**Command:**

```bash
sudo openssl genrsa -out /etc/ssl/private/svoboda.key 4096
```

**Verification:**

```
vagrant@svoboda:~$ sudo openssl rsa -in /etc/ssl/private/svoboda.key -check
RSA key ok
writing RSA key
-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQCymrNYUOciajNw
xz3Ns7Guu0VxWsPxNBfmcmsiZggyp8gP0QPonHlxUMcpp6QSej/cwwAtQ5OUsjhr
[... key truncated for brevity ...]
-----END PRIVATE KEY-----
```

### 2.2 Self-Signed Certificate Generation

**Command:**

```bash
sudo openssl req -new -x509 -key /etc/ssl/private/svoboda.key -out /etc/ssl/certs/svoboda.crt -days 365
```

### 2.3 Certificate Inspection

**`openssl x509 -text -noout` output:**

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            38:45:39:c9:1f:26:e4:2e:37:08:78:32:3b:7c:f3:5f:9a:c3:8e:49
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = MX, ST = " Juan Limberg Hernandez del Rio", L = Merida, O = Anahuac,
                OU = TI, CN = Limberg, emailAddress = hernandezdelriojuan@gmail.com
        Validity
            Not Before: May  5 22:27:54 2026 GMT
            Not After : May  5 22:27:54 2027 GMT
        Subject: C = MX, ST = " Juan Limberg Hernandez del Rio", L = Merida, O = Anahuac,
                 OU = TI, CN = Limberg, emailAddress = hernandezdelriojuan@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                0C:6C:D2:49:22:17:90:58:2B:58:4E:B1:E9:1D:BC:6E:DF:2B:AC:57
            X509v3 Authority Key Identifier:
                0C:6C:D2:49:22:17:90:58:2B:58:4E:B1:E9:1D:BC:6E:DF:2B:AC:57
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
```

**Field Analysis:**

| Field                | Value from Certificate                                                          | Notes                                                                                     |
| -------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Issuer               | C=MX, ST=Juan Limberg Hernandez del Rio, L=Merida, O=Anahuac, OU=TI, CN=Limberg | Quien firmó el certificado                                                                |
| Subject              | C=MX, ST=Juan Limberg Hernandez del Rio, L=Merida, O=Anahuac, OU=TI, CN=Limberg | Igual que Issuer — Sí, es autofirmado: el servidor es tanto sujeto como autoridad emisora |
| Serial Number        | 38:45:39:c9:1f:26:e4:2e:37:08:78:32:3b:7c:f3:5f:9a:c3:8e:49                     | Identificador único del certificado                                                       |
| Not Before           | May 5 22:27:54 2026 GMT                                                         | Inicio de validez                                                                         |
| Not After            | May 5 22:27:54 2027 GMT                                                         | Expira en un año                                                                          |
| Public Key Algorithm | rsaEncryption                                                                   | RSA                                                                                       |
| Key Size             | 4096 bit                                                                        | Clave de alta seguridad                                                                   |
| Signature Algorithm  | sha256WithRSAEncryption                                                         | SHA-256 con RSA                                                                           |

---

## Part 3: Apache TLS Configuration

### 3.1 Modules Enabled

```bash
vagrant@svoboda:~$ sudo a2enmod ssl
Considering dependency setenvif for ssl:
Module setenvif already enabled
Considering dependency mime for ssl:
Module mime already enabled
Considering dependency socache_shmcb for ssl:
Enabling module socache_shmcb.
Enabling module ssl.
To activate the new configuration, you need to run:
  systemctl restart apache2

vagrant@svoboda:~$ sudo a2enmod headers
Enabling module headers.
To activate the new configuration, you need to run:
  systemctl restart apache2

vagrant@svoboda:~$ sudo a2ensite default-ssl
Enabling site default-ssl.
To activate the new configuration, you need to run:
  systemctl reload apache2
```

### 3.2 SSL VirtualHost Configuration

**`/etc/apache2/sites-available/default-ssl.conf` full contents:**

```apache
<IfModule mod_ssl.c>
        <VirtualHost _default_:443>
                ServerAdmin webmaster@localhost
                DocumentRoot /var/www/html

                ErrorLog ${APACHE_LOG_DIR}/error.log
                CustomLog ${APACHE_LOG_DIR}/access.log combined

                SSLEngine on

                SSLCertificateFile      /etc/ssl/certs/svoboda.crt
                SSLCertificateKeyFile /etc/ssl/private/svoboda.key
                Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
                SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
                SSLCipherSuite HIGH:!aNULL:!MD5:!3DES

                <FilesMatch "\.(cgi|shtml|phtml|php)$">
                                SSLOptions +StdEnvVars
                </FilesMatch>
                <Directory /usr/lib/cgi-bin>
                                SSLOptions +StdEnvVars
                </Directory>
        </VirtualHost>
</IfModule>
```

**`apache2ctl configtest` output:**

```
AH00558: apache2: Could not reliably determine the server's fully qualified domain name,
using 127.0.2.1. Set the 'ServerName' directive globally to suppress this message
Syntax OK
```

### 3.3 HTTPS Verified Working

**`curl -k https://localhost` output:**

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>SVOBODA Network — Internal Portal</title>
  </head>
  <body>
    <h1>SVOBODA Network — Internal Coordination Portal</h1>
    <p>Welcome, operative. This portal is for authorized team use only.</p>
    <p>Current active contacts: <strong>14</strong></p>
    <p>Next document release: <strong>72 hours</strong></p>
    <p>Secure drop: <strong>operative-drop@svoboda.internal</strong></p>
  </body>
</html>
```

**`openssl s_client` certificate verification:**

```bash
echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

```
subject=C = MX, ST = " Juan Limberg Hernandez del Rio", L = Merida, O = Anahuac,
        OU = TI, CN = Limberg, emailAddress = hernandezdelriojuan@gmail.com
issuer=C = MX, ST = " Juan Limberg Hernandez del Rio", L = Merida, O = Anahuac,
       OU = TI, CN = Limberg, emailAddress = hernandezdelriojuan@gmail.com
notBefore=May  5 22:27:54 2026 GMT
notAfter=May  5 22:27:54 2027 GMT
```

---

## Part 4: HTTP → HTTPS Redirect & HSTS

### 4.1 Redirect Configuration

**`/etc/apache2/sites-available/000-default.conf` relevant section:**

```apache
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        Redirect permanent / https://localhost/
</VirtualHost>
```

**`curl -v http://localhost` output (showing the 301):**

```
< HTTP/1.1 301 Moved Permanently
< Location: https://localhost/
< Content-Length: 301
<title>301 Moved Permanently</title>
```

### 4.2 HSTS Header

**HSTS directive added to `default-ssl.conf`:**

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

**`curl -k -I https://localhost` output (showing the HSTS header):**

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## Part 5: TLS Hardening

### 5.1 Hardening Directives Added

**Directives added to `default-ssl.conf`:**

```apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
```

### 5.2 nmap Protocol Verification

**`sudo nmap --script ssl-enum-ciphers -p 443 localhost` output:**

```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-05 22:45 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000042s latency).
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 4096) - A
|       TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (dh 4096) - A
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 4096) - A
|       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (dh 4096) - A
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
|     compressors:
|       NULL
|     cipher preference: client
|_  least strength: A
Nmap done: 1 IP address (1 host up) scanned in 0.69 seconds
```

> **Resultado:** Solo TLSv1.2 aparece en la salida. TLS 1.0 y TLS 1.1 están **ausentes** — correctamente deshabilitados.

### 5.3 openssl s_client Protocol Tests

**TLS 1.0 (should fail):**

```
40770F74567F0000:error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available:../ssl/statem/statem_lib.c:104:
```

**TLS 1.1 (should fail):**

```
40A7684AA47F0000:error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available:../ssl/statem/statem_lib.c:104:
```

**TLS 1.2 (should succeed):**

```
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
```

**TLS 1.3 (should succeed):**

```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
```

> **Nota sobre Ubuntu 22.04:** OpenSSL 3.x deshabilita TLS 1.0/1.1 también a nivel de cliente. El error `no protocols available` proviene del lado del cliente antes de llegar al servidor. La prueba autoritativa de la configuración **del servidor** es el output de `nmap --script ssl-enum-ciphers`, el cual confirma que únicamente TLSv1.2 está disponible.

---

## Part 6: Before & After — HTTP vs HTTPS on the Wire

### 6.1 HTTPS tcpdump Capture

```
vagrant@svoboda:~$ sudo tcpdump -i lo -A -s 0 'port 443'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
22:46:06.131397 IP localhost.53648 > localhost.https: Flags [P.], seq 1:518, length 517
E..9Z.@.@..:...............s..~............
..*v..*t...........,....2..1M\...../.N;D9.b.....D.. .:.~8..w..t.....g...s...j5s...b..>.......,.0.........+./...$.(.k.#.'.g.
...9.   ...3.....=.<.5./.....u........  localhost.........
[ciphertext — ilegible]
22:46:06.138943 IP localhost.https > localhost.53648: Flags [P.], seq 1:2417, length 2416
E.      ...@.@.lP..............~....x...........
..*}..*v....z...v..Y..>.Fd.D.m}h.. ............Gc*X .:.~8..w
[ciphertext — ilegible]
22:46:06.140044 IP localhost.53648 > localhost.https: Flags [P.], seq 518:598, length 80
..........E./D..y..wx.?.n..I.....&/.Bn..B@      s2...j.0..]I-R$d....i..5c}.r......1.C
[ciphertext — ilegible]
18 packets captured
36 packets received by filter
0 packets dropped by kernel
```

### 6.2 Side-by-Side Comparison

|                               | HTTP Capture (Part 1)                                       | HTTPS Capture (Part 6)                |
| ----------------------------- | ----------------------------------------------------------- | ------------------------------------- |
| Destination URL visible?      | Sí — `GET /contacts.html HTTP/1.1`                          | No — solo se ve IP y puerto destino   |
| Authorization header visible? | Sí — `Authorization: Basic c3Zvb29kYTpzZWNyZXQxMjM=`        | No — cifrado                          |
| Page content readable?        | Sí — HTML completo con lista de fuentes clasificadas        | No — ciphertext ilegible              |
| Other headers exposed?        | Sí — `Host`, `User-Agent`, `Server`, `Content-Type`, `ETag` | No — todos los headers están cifrados |

### 6.3 Written Analysis

**The Interceptor's 21-Day Access:**

Durante 21 días, el interceptor del nodo SVOBODA tuvo acceso completo a todo el tráfico HTTP en texto plano. Esto incluía las credenciales de autenticación de cada operativo que ingresaba al portal — usuario y contraseña en Base64, trivialmente decodificable con un solo comando. Con esas credenciales, el interceptor podía autenticarse en el sistema en cualquier momento, acceder a la lista de fuentes activas (ATLAS, WRAITH, FALCON) con sus ubicaciones reales, y correlacionar cada acceso con una identidad. Adicionalmente, los metadatos expuestos — `User-Agent`, timestamps, dirección IP de origen, patrones de acceso — permitirían construir un perfil de comportamiento operativo completo. En un escenario real, el interceptor no solo leería información: podría modificar respuestas en tránsito (ataque MITM activo), inyectar contenido falso, o simplemente vender la lista de fuentes a actores hostiles. Tres semanas de acceso a un portal de periodistas de investigación en Europa Central representaría una catástrofe de seguridad operacional.

**What TLS Protects — and What It Does Not:**

La captura de la Parte 1 muestra el request completo en texto plano: URL, headers, credenciales y contenido HTML. La captura de la Parte 6 muestra únicamente ruido cifrado — ningún header, ninguna URL, ningún dato de aplicación es legible. TLS protege la confidencialidad e integridad de todo el payload HTTP: headers, body, cookies y credenciales. Sin embargo, TLS **no oculta** la dirección IP de destino ni el puerto: esto es necesario porque el routing de red ocurre en la capa 3/4, por debajo de TLS que opera en capa 4/7. Un observador en la red seguirá viendo que alguien se conectó a `127.0.0.1:443`, con qué frecuencia y cuántos bytes transfirió — pero no sabrá qué pidió ni qué recibió.

**The `-k` Flag and Its Risk:**

`curl -k` deshabilita la verificación del certificado del servidor. Normalmente, cuando un cliente se conecta a un servidor HTTPS, verifica que el certificado presentado esté firmado por una CA de confianza y que el CN coincida con el hostname. Al usar `-k`, el cliente acepta cualquier certificado — incluso uno falso generado por un atacante. Esto abre la puerta a ataques de Man-in-the-Middle: un adversario interpuesto en la red puede presentar su propio certificado autofirmado, el cliente lo acepta sin verificar, y el canal "cifrado" en realidad pasa por el atacante. En producción, nunca se debe usar `-k` — se utiliza en este lab únicamente porque nuestro certificado es autofirmado y no está validado por ninguna CA de confianza. Un certificado firmado por Let's Encrypt o cualquier CA pública eliminaría la necesidad de este flag.

**HSTS — Why It Matters:**

HSTS (HTTP Strict Transport Security) le indica al navegador que **nunca** intente conectarse a este dominio por HTTP, durante el período `max-age` especificado (en nuestro caso, un año). Sin HSTS, aunque tengamos un redirect 301 de HTTP a HTTPS configurado, un atacante puede interceptar esa primera petición HTTP antes de que ocurra el redirect — el llamado SSL stripping attack. El navegador hace la petición inicial en HTTP, el atacante la intercepta, establece HTTPS con el servidor real en nombre del cliente, y mantiene al cliente en HTTP sin que este lo sepa. Con HSTS activo y previamente recibido, el navegador se niega a hacer la petición HTTP inicial desde el principio, eliminando la ventana de ataque. Es una capa de defensa indispensable incluso cuando TLS está correctamente configurado.

---

## Final Verification Checklist

```bash
# Run all five checks and paste output here
curl -v http://localhost 2>&1 | grep "301\|Location"
curl -k https://localhost | grep "SVOBODA"
echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -subject
sudo nmap --script ssl-enum-ciphers -p 443 localhost | grep -E "TLSv|SSLv"
curl -k -I https://localhost | grep -i strict
```

```
# 1. HTTP redirects to HTTPS
< HTTP/1.1 301 Moved Permanently
< Location: https://localhost/
< Content-Length: 301
<title>301 Moved Permanently</title>

# 2. HTTPS serves the page
  <title>SVOBODA Network — Internal Portal</title>
  <h1>SVOBODA Network — Internal Coordination Portal</h1>

# 3. Certificate is ours
subject=C = MX, ST = " Juan Limberg Hernandez del Rio", L = Merida, O = Anahuac,
        OU = TI, CN = Limberg, emailAddress = hernandezdelriojuan@gmail.com

# 4. TLS 1.0/1.1 are disabled
|   TLSv1.2:

# 5. HSTS header is present
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
