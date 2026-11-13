# Versionshinweise

## Noch nicht veröffentlicht – 13. November 2026

- Öffentliche DENIC-Web-WHOIS-Abfrage aus dem bereitgestellten Domainanalysator übernommen: öffentliche Inhaber-/Vereinsangaben, verwaltendes Mitglied und Datumsangaben statt eines bloßen manuellen Verweises.
- WHOIS-Inhaber-, Organisations- und Kontaktfelder einschließlich Privacy-Platzhaltern werden strukturiert angezeigt und bei langen Nameserverlisten priorisiert.
- Bei Verbindungsfehlern werden weitere geprüfte öffentliche WHOIS-IP-Adressen versucht. Proxy-Ablehnungen werden konkret ausgewiesen, ohne direkten Ausweichversuch.

## 0.4.0 – 7. November 2026

- DENIC-RDAP für .de-Domains direkt eingebunden, auch ohne Eintrag im IANA-DNS-Verzeichnis. Der Bericht unterscheidet technische Daten und die separate DENIC-Web-WHOIS-Inhaberauskunft.
- Registrar-RDAP über die IANA-Registrar-ID ergänzt, wenn die Registry keinen RDAP-Link liefert. Die bestehenden WHOIS-/RDAP-Abfrageketten und ihre Abfragelimits bleiben erhalten.
- Veröffentlichte Kontakte, Organisationen, verschachtelte Kontaktrollen und Datenschutz-/Redigierungshinweise werden in Ansicht und PDF ausgegeben. Aus fehlenden Angaben wird kein Datenschutzstatus erfunden.
- Mail-Header-Berichte mit verständlichen SPF-/DKIM-/DMARC-Ergebnissen, geprüften Domains und Bedeutung für Versandberechtigung bzw. mögliche Absenderfälschung. Unterschiedliche Prüfsysteme, fehlende Ergebnisse und technische Prüffehler werden getrennt ausgewiesen.
- IP-Verzeichnis mit Fundstellen, Adresstyp und erkennbarer Rolle im Transportweg: möglicher Einlieferungs-Endpunkt, Zwischenstation oder Empfangsserver.
- Wiederholte Verifikationshinweise gestrafft und PDF-Umbrüche zwischen Abschnittsüberschriften und Inhalt verbessert.

Die Domainabfragen sind mit simulierten Antworten geprüft; ein Live-Abgleich mit allen Registrierungsdiensten ist damit nicht belegt. Die öffentlich verfügbaren Organisationsinhaber von .de-Domains werden weiterhin separat im DENIC-Web-WHOIS abgefragt.
