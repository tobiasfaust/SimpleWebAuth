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
3. secret.key erzeugen
```
umask 077
openssl rand -hex 32 > /var/www/SimpleWebAuth/secret.key
chown www-data:www-data /var/www/SimpleWebAuth/secret.key
chmod 600 /var/www/SimpleWebAuth/secret.key
```
## Apache Konfiguration

1. PHP aktivieren, zb. in der `sites-avaliable/00-ssl.conf`:

2. Auth-Middleware aktivieren:
im apache eine neue konfiguration anlegen: `sites-available/20-simplewebauth.conf`

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
