# Auth-Mini-WebProject

## Zweck
Dieses Projekt bietet passwortlose Authentifizierung per QR-Code (Magic-Link) mit persistentem Cookie.
Geeignet für iOS Safari + Apache + mod_proxy.

## Installation

1. ZIP entpacken:
```
unzip Auth-Mini-WebProject.zip -d /var/www/html/
```
2. Rechte setzen:
```
chown -R www-data:www-data /var/www/html/Auth-Mini-WebProject
chmod -R 700 /var/www/html/Auth-Mini-WebProject/auth
```

## Apache Konfiguration

1. PHP aktivieren:
```
AddType application/x-httpd-php .php
```
2. Auth-Middleware aktivieren:
```
php_value auto_prepend_file "/var/www/html/Auth-Mini-WebProject/auth/check.php"
```
3. Proxy-Apps absichern:
```
<Location /app1/>
    ProxyPass http://127.0.0.1:8080/
    ProxyPassReverse http://127.0.0.1:8080/
    Require all granted
</Location>
<Location /app2/>
    ProxyPass http://127.0.0.1:8081/
    ProxyPassReverse http://127.0.0.1:8081/
    Require all granted
</Location>
```
Backend-Apps nur intern binden:
```
listen 127.0.0.1:8080
```

## Nutzung

1. Admin öffnet `/admin/users.php`
2. QR-Code für Magic-Link erzeugen
3. iOS scannt → Cookie wird gesetzt
4. Zugriff auf `/app1` oder `/app2` funktioniert automatisch

## Sicherheit

- HTTPS Pflicht
- Magic-Link Token einmalig (5-15 Minuten gültig)
- Session-Cookie 30 Tage gültig
- Backend nie öffentlich erreichbar
- Audit-Log in `auth/audit/YYYY-MM-DD.log`
