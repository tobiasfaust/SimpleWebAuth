# Auth-Mini-WebProject

## Zweck
Dieses Projekt bietet passwortlose Authentifizierung per QR-Code (Magic-Link) mit persistentem Cookie.
Geeignet für iOS Safari + Apache + mod_proxy.

## Installation

1. git clonen:
Das Apache publich html verzeichnis ist `/var/ww/html/`
```
git clone https://github.com/tobiasfaust/SimpleWebAuth.git /var/www/SimpleWebAuth/
```
2. Rechte setzen:
```
chown -R www-data:www-data /var/www/SimpleWebAuth/
chmod -R a+X /var/www/SimpleWebAuth/
```

## Apache Konfiguration

1. PHP aktivieren, zb. in der `sites-avaliable/00-ssl.conf`:
```
AddType application/x-httpd-php .php
```
2. Auth-Middleware aktivieren:
im apache eine neue konfiguration anlegen: `sites-available/20-simplewebauth.conf`
```
Alias /auth /var/www/SimpleWebAuth/public/
Alias /authadmin /var/www/SimpleWebAuth/admin/

<Directory /var/www/SimpleWebAuth/admin/>
  AddDefaultCharset UTF-8
  <IfModule mod_authz_core.c>
     <RequireAll>
       Require ip 192.168.10.0/24
     </RequireAll>
  </IfModule>
</Directory>
```

3. innerhalb des <VirtualHost> (außerhalb von <Location>) integrieren: `sites-available/00-ssl.conf`
```
RewriteMap authcheck "prg:/usr/bin/env php /var/www/SimpleWebAuth/bin/validate_auth.php"
```

3. die zu sichernde interne Applikation für den Apachen konfigurieren: `sites-available/10-fhem.conf`

4. Konfigurationen im apache aktivieren
```
a2ensite 00-ssl 10-fhem 20-simplewebauth
a2enmod ssl headers rewrite proxy_http proxy_html proxy_wstunnel
```

5. Backend-Apps nur intern binden:
```
listen 127.0.0.1:8080
```

## Nutzung

1. Admin öffnet `/authadmin/users.php`
2. QR-Code für Magic-Link erzeugen
3. iOS scannt → Cookie wird gesetzt
4. Zugriff auf `/fhem funktioniert` automatisch

## Sicherheit

- HTTPS Pflicht
- Magic-Link Token einmalig (5-15 Minuten gültig)
- Session-Cookie 30 Tage gültig (HMAC-signiert, pro Anfrage validiert)
- Backend nie öffentlich erreichbar
- Audit-Log in `/var/www/SimpleWebAuth/audit/YYYY-MM-DD.log`
- Audit-Log einsehbar unter `/authadmin/index.php` -> `Audit`
