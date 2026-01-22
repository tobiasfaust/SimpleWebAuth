# Audit-Verzeichnis

Dieser Ordner dient der Ablage von Audit-Daten für SimpleWebAuth. Er ermöglicht die Nachvollziehbarkeit sicherheitsrelevanter Ereignisse (z. B. Anmeldungen, Token-Ausstellungen, fehlgeschlagene Zugriffe).

## Inhalt
- Audit-Logs (maschinenlesbar, z. B. JSON)
- Zusammenfassungen/Reports
- Relevante Artefakte zur Prüfung (z. B. Signatur- oder Header-Belege)

## Betrieb
- Schreibzugriff nur durch den Webdienst; kein öffentlicher Zugriff
- Logrotation und Aufbewahrung gemäß Compliance-Richtlinien (z. B. 90 Tage; anpassen)
- Zeitstempel in UTC, eindeutige Ereignis-IDs

## Datenschutz
- Kann personenbezogene Daten enthalten: Zugriff strikt einschränken
- Verschlüsselung und revisionssichere Ablage empfehlen
- Lösch- und Aufbewahrungsfristen dokumentieren und einhalten