## Zweck
Dieses Projekt bietet browserbasierte passwortlose Authentifizierung per QR-Code (Magic-Link) oder Login mit persistentem Cookie. Es soll eine einfache Basic-Auth ersetzen.
Falls ein gültiges Authentifizierungs-cookie vorliegt wird man transparent zur Applikation weitergeleitet. Andernfalls muss man sich einmal anmelden um das Cookie zu setzen. Anschließend wird man zur Applikation weitergeleitet.
<br>
Voraussetzungen ist der Betrieb und Konfiguration eines eigenen Apache2 Webservers.

## Installation

1. git clonen:
Das Apache publich html verzeichnis ist `/var/www/html/`
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
4. PHPMailer installieren
```
apt-get update
apt-get install -y --no-install-recommends git whois openssl ca-certificates composer zip unzip

COMPOSER_ALLOW_SUPERUSER=1 composer --working-dir=/var/www require phpmailer/phpmailer:^6.9 --no-interaction --prefer-dist
chown -R www-data:www-data /var/www
```
5. initialen user setzen um sich im admin bereich einloggen zu können
```
ts="$(date +%s)"
pw_hash="$(mkpasswd --method=bcrypt --rounds=10 'password')"
cat > /var/www/SimpleWebAuth/users/user1.json <<EOF
{"id":"user1","email":"user1@example.com","updated_at":$ts,"cookie_exp_seconds":3600,"last_cookie_created_at":0,"enabled":1,"password_hash":"$pw_hash","last_pw_generated_at":$ts}
EOF
```
## Apache Konfiguration

1. PHP aktivieren, zb. in der `sites-avaliable/00-ssl.conf`:

2. Auth-Middleware aktivieren:
im apache eine neue konfiguration anlegen: `sites-available/20-simplewebauth.conf`
Das lokale Netz ggf anpassen, im beispiel ist es `192.168.10`

3. die zu sichernde interne Applikation für den Apachen konfigurieren: `sites-available/10-fhem.conf`
Für jede weitere interne Applikation kann das 10-fhem beispiel kopiert und als neue Datei angepasst werden.

4. Konfigurationen im apache aktivieren
```
a2ensite 00-ssl 10-fhem 20-simplewebauth
a2enmod ssl headers rewrite proxy_http proxy_html proxy_wstunnel
```

5. Backend-Apps nur intern binden:
```
listen 127.0.0.1:8080
```
... oder zumindest sicherstellen das diese nicht aus dem Internet erreichbar sind

## initiale Admin-Konfiguration

1. <b>WICHTIG</b>: der `/authadmin` Bereich ist ausschliesslich aus dem lokalen Netz ereichbar!
1. Admin öffnet `/authadmin` -> Einstellungen
1. wenn `/authadmin` nicht verfügbar ist, in `20-simplewebauth.conf` das lokale Netz kontrollieren.
1. Emailserver Einstellungen setzen
1. globale Einstellungen setzen, insbesondere `Composer Autoload Pfad` setzen. (siehe _PHP Mailer installation_ -> _working_dir_)
1. Test-Email absenden 

## Benutzerkonfiguration anlegen
1. Admin öffnet `/authadmin` -> Userverwaltung
1. einen neuen User mit korrekter Emailadresse anlegen
1. entweder gleich auf dem GErät mittels QR-Code Button den Token setzen oder später mittels initialem Login mit dem neuen User
1. aus dem Adminbereich ausloggen
1. wenn das folgende Login mit dem neuen User erfolgreich war, den initialen User im Adminbereich löschen. 

## Nutzung

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
