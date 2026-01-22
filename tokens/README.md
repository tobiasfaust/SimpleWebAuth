# SimpleWebAuth Tokens

Dieser Ordner dient zur Ablage kurzlebiger Token-Artefakte für SimpleWebAuth (z. B. Sitzungs- oder Ausstellungsinformationen). Die Inhalte sind temporär und werden vom Dienst bei Bedarf neu erstellt.

Hinweise:
- Sensible Daten: Ordner und Dateien mit restriktiven Rechten betreiben (z. B. 700 für den Ordner, 600 für Dateien).
- Nicht versionieren: Den Ordner in der Versionskontrolle ignorieren (z. B. Eintrag „tokens/“ in .gitignore).
- Aufräumen: Abgelaufene Tokens regelmäßig entfernen/rotieren.
- Produktion: Statt Dateisystem bevorzugt einen sicheren, zentralen Speicher (z. B. Datenbank oder Keystore) verwenden.
- Backup: Keine Backups dieses Ordners erstellen, um Risiken zu minimieren.