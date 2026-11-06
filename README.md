# Web Forensics

Selbst gehostete Webanwendung von **gl1tchb1rd** für Domain- und E-Mail-Header-Analysen. Dunkle Oberfläche, sachliche A4-PDF-Berichte und ein verpflichtendes Aktenzeichen in jedem Modul. Programmversion: **0.3.0** (Entwicklungsstand bis zur Veröffentlichung eines Releases).

Keine Datenbank, Benutzerkonten, Berichtablage, KI-Anbindung oder Telemetrie. Alle Browserressourcen werden lokal ausgeliefert. Optionaler gemeinsamer Passwortschutz ist direkt integriert; TLS und weitere Zugangsregeln konfiguriert der Betreiber beispielsweise an seinem Reverse-Proxy.

![Startseite von Web Forensics](docs/preview.png)

## Start mit Docker auf Linux

Voraussetzungen: Docker Engine und Docker Compose v2. Das Image wird lokal aus diesem Repository gebaut; ein veröffentlichtes Registry-Image wird nicht vorausgesetzt. Für eine reguläre Installation einen veröffentlichten stabilen Tag auf der [GitHub-Releases-Seite](https://github.com/gl1tchb1rd/web_forensics/releases) wählen und `vX.Y.Z` im folgenden Befehl ersetzen. Ein Tag allein genügt nicht: Er muss zu einem veröffentlichten Release gehören. Falls noch kein Release veröffentlicht ist, gibt es noch keinen regulären Installations-/Updatekanal. Die Anwendung veröffentlicht selbst keine Releases.

```sh
git clone --branch vX.Y.Z --single-branch https://github.com/gl1tchb1rd/web_forensics.git
cd web_forensics
docker compose up --build -d
```

Die Standardkonfiguration bindet ausschließlich an `127.0.0.1:8000`. Ein lokaler Browser kann die Anwendung dort öffnen. Der optionale Passwortschutz ist standardmäßig ausgeschaltet; es gibt kein voreingestelltes Passwort. Bei einem Remote-Server kann für einen ersten Test ein SSH-Tunnel verwendet werden:

```sh
ssh -L 8000:127.0.0.1:8000 benutzer@dein-server
```

Gesundheit prüfen und Anwendung stoppen:

```sh
docker compose ps
docker compose exec web python -c "import urllib.request; print(urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:8000/healthz').read().decode())"
docker compose down
```

### Optionaler Passwortschutz

In `.env` (Vorlage: `.env.example`) oder der Containerumgebung konfigurieren:

| Variable | Bedeutung | Standard |
| --- | --- | --- |
| `WF_AUTH_ENABLED` | `1` aktiviert, `0` deaktiviert den Passwortschutz | `0` |
| `WF_AUTH_USERNAME` | Gemeinsamer Benutzername | `admin` |
| `WF_AUTH_PASSWORD` | Selbst gewähltes, langes und eindeutiges Passwort | leer |

Bei Aktivierung fragt der Browser per **HTTP Basic Authentication** nach Benutzername und Passwort. Alle Oberflächen, statischen Ressourcen, Abfragepläne, Analysen und PDF-Downloads sind geschützt. Ausschließlich `/healthz` bleibt für die Docker-Gesundheitsprüfung frei und liefert nur Status und Softwareversion. Es werden keine Benutzerkonten, Anmeldesitzungen oder Zugriffsprotokolle gespeichert. Der Browser sendet die Zugangsdaten bei weiteren Anfragen an dieselbe Instanz erneut; die Anwendung gibt sie nicht an externe Analysedienste weiter.

Fehlt bei aktiviertem Schutz das Passwort, verweigert die Anwendung den Start. Ein leerer/ungültiger Benutzername oder ein unbekannter Schalterwert werden ebenfalls abgewiesen, statt den Schutz stillschweigend abzuschalten. Änderungen werden beim nächsten Containerstart geladen; nach einer Änderung in `.env` den Container mit aktualisierter Umgebung neu erstellen:

```sh
docker compose up --build -d --force-recreate
```

Zum Abschalten `WF_AUTH_ENABLED=0` setzen und ebenfalls neu erstellen. Ein bloßes `docker compose restart` übernimmt geänderte Umgebungsvariablen nicht. `.env` gehört nicht ins Git-Repository (bereits ignoriert); Dateizugriff beispielsweise mit `chmod 600 .env` auf den Betreiber beschränken. Passwörter mit `$`, `#` oder Leerzeichen in Compose-`.env` in einfache Anführungszeichen setzen, damit sie wörtlich gelesen werden.

HTTP Basic verschlüsselt die Zugangsdaten nicht selbst. Für entfernten Zugriff HTTPS oder einen SSH-Tunnel verwenden. Die Browser speichern Basic-Zugangsdaten vorübergehend selbst; die Anwendung hat keinen verlässlichen Abmeldeknopf. Zum Beenden die Browser-Anmeldedaten löschen bzw. ein separates privates Browserfenster vollständig schließen. Die Bereinigung der Analyseergebnisse nach dem PDF-Download bleibt unabhängig davon aktiv. Es handelt sich um einen gemeinsamen Zugang, ohne Rollen oder individuelle Konten; ergänzende Begrenzung von Anmeldeversuchen kann am Reverse-Proxy erfolgen.

### Betrieb hinter einem Reverse-Proxy

Die Vorlage `.env.example` enthält HTTP-Einstellungen für lokalen Zugriff bzw. einen SSH-Tunnel. Für eine öffentliche HTTPS-Domain die eigene `.env` anpassen, beispielsweise (Beispieldomain ersetzen):

```dotenv
WF_ALLOWED_HOSTS=localhost,127.0.0.1,[::1],forensics.example.org
WF_HTTPS=1
WF_TRUSTED_ORIGINS=https://forensics.example.org
```

`WF_ALLOWED_HOSTS` enthält Hostnamen **ohne** Protokoll oder Port, `WF_TRUSTED_ORIGINS` vollständige Browseradressen **mit** Protokoll und gegebenenfalls Port, ohne abschließenden Schrägstrich. Mehrere Einträge werden durch Kommas getrennt. Die Hostliste muss `127.0.0.1` für die Container-Gesundheitsprüfung enthalten.

`WF_HTTPS=1` deklariert die öffentliche Verbindung als HTTPS: Django berücksichtigt das für die Herkunftsprüfung auch dann, wenn der Reverse-Proxy intern HTTP verwendet. Außerdem erhält das CSRF-Cookie das Secure-Attribut. Diese Einstellung ist explizit; die Anwendung leitet den Modus nicht aus beliebigen `X-Forwarded-Proto`-Headern ab. `WF_HTTPS=0` ist für Zugriff über HTTP vorgesehen. Beide Zugriffsarten nicht auf derselben Installation mischen.

Wenn der Proxy den öffentlichen `Host` einschließlich eines abweichenden Browserports erhält, ist dieselbe HTTPS-Herkunft automatisch gültig; `WF_TRUSTED_ORIGINS` kann dann leer bleiben. Für einen Proxy, der den Host umschreibt, sind sowohl der interne Host in `WF_ALLOWED_HOSTS` als auch die öffentliche Browseradresse in `WF_TRUSTED_ORIGINS` erforderlich. Empfohlen ist das Erhalten des öffentlichen Hosts.

Der Reverse-Proxy muss den öffentlichen `Host` erhalten und kann an den lokalen Port 8000 weiterleiten. Bei Nutzung des integrierten Passwortschutzes muss er außerdem den `Authorization`-Header durchreichen. Schreibzugriffe auf Disk, Access-/Error-Logs, Request-Body-Dumps, Tracing, Caching und Antwortpuffer auf Disk müssen dort entsprechend deaktiviert werden. Ein Request-Limit von 2 MiB und ein Upstream-Zeitlimit von 150 Sekunden passen zur Anwendung. Zusätzliche Authentifizierung und gegebenenfalls Rate Limits können am Proxy eingerichtet werden. Öffentliches HTTPS wird am Proxy terminiert; die Anwendung vertraut nicht pauschal eingehenden Forwarded-Headern.

Für Nginx gehört dazu insbesondere `proxy_set_header Host $http_host;`, damit auch ein eventuell verwendeter Browserport erhalten bleibt. Cookie- und `X-CSRFToken`-Header unverändert weiterreichen.

Der Container läuft als UID/GID `10001`, mit schreibgeschütztem Root-Dateisystem, ohne zusätzliche Capabilities, ohne persistente Volumes und ohne Docker-Protokollierung. Gunicorn nutzt `/dev/shm` nur für seine Worker-Verwaltung. Das Speicherlimit beträgt 512 MiB, zusätzlicher Container-Swap und Core-Dumps sind in Compose deaktiviert. Die tatsächlichen Host-Funktionen müssen diese Einstellungen unterstützen.

### Sicherheitsprüfung / CSRF-Fehler beheben

Ab Version 0.1.1 nennt die Fehlermeldung den konkreten Bereich, ohne Eingaben, Cookies oder Anmeldedaten zu protokollieren:

| Fehlercode | Bedeutung / Korrektur |
| --- | --- |
| `invalid_host` | Öffentliche Domain fehlt in `WF_ALLOWED_HOSTS`, oder der Proxy setzt einen anderen Host. Die Seite wird bereits beim Öffnen abgewiesen. |
| `csrf_origin_mismatch` | HTTPS-Modus, Browseradresse oder vom Proxy übermittelter Host stimmen nicht überein. `WF_HTTPS`, `Host` und bei Bedarf `WF_TRUSTED_ORIGINS` wie oben prüfen. |
| `csrf_https_mismatch` | HTTP-Browseranfrage an eine als HTTPS konfigurierte Installation. Über HTTPS öffnen; für einen reinen HTTP-Test `WF_HTTPS=0` setzen. |
| `csrf_cookie_missing` | Browser sendet kein gültiges Sicherheitscookie. Cookies für die Website zulassen und den HTTPS-/HTTP-Modus prüfen. |
| `csrf_token_missing` / `csrf_token_invalid` | Seitentoken fehlt oder passt nicht zum Cookie. Seite vollständig neu laden; alte Tabs schließen. Der Proxy muss `X-CSRFToken` erhalten. |
| `csrf_referer_invalid` | HTTPS-Anfrage ohne gültige Herkunftsangabe. Anwendung regulär im Browser öffnen und Proxy-/Herkunftseinstellungen prüfen. |

Eine geänderte `.env` übernehmen, ohne eigene Zugangsdaten zu überschreiben:

```sh
docker compose up --build -d --force-recreate
```

Für neue Programmversionen ausschließlich die Anleitung der Release-Prüfung verwenden (siehe unten), keine Aktualisierung vom Entwicklungsbranch.

Danach den Browser vollständig neu laden. Die Anwendung verwendet jetzt ein eigenes Cookie namens `wf_csrftoken`, damit ein gewöhnliches `csrftoken` einer anderen Django-Anwendung auf derselben Domain die Analyse nicht stört. CSRF-Prüfung und Secure-Cookies bei HTTPS bleiben aktiv. Keine echte `.env`, Passwörter oder Cookie-/Authorization-Header zur Fehlerdiagnose veröffentlichen.

### Eigenes Logo

Die Oberfläche lädt das Logo aus `static/brand/logo.png` und zeigt es im Kopfbereich sowie groß auf der Startseite. Es wird ausschließlich lokal ausgeliefert; die Webseite bindet kein externes Avatarbild ein. Eine eigene PNG-Datei kann an dieser Stelle hinterlegt oder schreibgeschützt nach `/app/static/brand/logo.png` gemountet werden. Falls die Datei fehlt, erscheint der lokale Schriftzug als Fallback.

Die PDF-Berichte verwenden ausschließlich den Programmnamen **Web Forensics**, die genaue Softwareversion und einen anklickbaren Link zum [Programm-Repository](https://github.com/gl1tchb1rd/web_forensics). Das farbige Logo und der Markenname werden nicht als Berichtsbranding verwendet; der GitHub-Benutzername ist lediglich Bestandteil der Repository-Adresse.

### Nur veröffentlichte Releases prüfen und installieren

Die Startseite bietet **GitHub-Releases prüfen**. Erst der Klick löst einen serverseitigen GET auf `https://api.github.com/repos/gl1tchb1rd/web_forensics/releases/latest` aus. Beim Seitenaufruf gibt es keine Hintergrundabfrage. Es werden weder Untersuchungsdaten noch Zugangsdaten, Cookies oder die installierte Versionsnummer an GitHub gesendet. GitHub sieht die Absender-IP der Installation bzw. des Proxys und einen festen technischen User-Agent. Ausgehender HTTPS-Zugriff auf `api.github.com` ist dafür erforderlich; es wird kein GitHub-Token benötigt. Private Repositories ohne öffentlich abrufbare Releases werden nicht unterstützt.

Die Funktion verwendet ausschließlich den von GitHub als aktuell ausgewiesenen veröffentlichten regulären Release. **Commits auf `main`, einzelne Git-Tags, Entwürfe und Vorabversionen werden nicht als Updates angeboten.** Release-Tags müssen stabile Versionsnummern wie `v1.2.3` oder `1.2.3` verwenden. Es gibt keine automatische Installation und keinen serverseitigen Git-/Docker-Aufruf.

Ist die Release-Versionsnummer höher als die installierte Version, erscheinen der Release-Link und ein kopierbarer Befehlsblock. Beispiel für einen tatsächlich veröffentlichten Release `v1.2.3`:

```sh
test -z "$(git status --porcelain)" &&
git fetch --no-tags https://github.com/gl1tchb1rd/web_forensics.git refs/tags/v1.2.3:refs/tags/v1.2.3 &&
git switch --detach refs/tags/v1.2.3 &&
docker compose up --build -d --force-recreate
```

Der Block im bestehenden Checkout stoppt bei lokalen Änderungen, einem fehlgeschlagenen Fetch oder einem fehlenden Tag. Er verändert keinen Entwicklungsbranch, überschreibt keine lokalen Änderungen und lässt die ignorierte `.env` erhalten. Bei einem Stopp zunächst `git status --short` prüfen. Der Detached-HEAD-Zustand ist für die Bereitstellung eines exakten Release-Tags beabsichtigt. Danach die Browserseite vollständig neu laden. Das Abrufen des Tags erfolgt nur auf dem Server des Betreibers, wenn dieser die Anleitung selbst ausführt.

Eine nicht erreichbare GitHub-API oder ein Abfragelimit wird als Fehler angezeigt, niemals als „aktuell“. Gibt es keinen öffentlich abrufbaren regulären Release, erscheinen keine Updatebefehle. Ist die installierte Versionsnummer höher, wird kein Downgrade angeboten. Die Funktion bestätigt die Versionsnummer, nicht die Herkunft beliebiger lokaler Codeänderungen.

Für den Herausgeber: Zunächst `webforensics/__init__.py` und den Image-Tag in `compose.yaml` auf die gewünschte Versionsnummer setzen. Anschließend auf GitHub einen dazu passenden Tag auswählen/erstellen und den regulären Release ausdrücklich veröffentlichen. Ein Push auf `main` oder das Erstellen eines Tags allein löst keinen Updatehinweis aus. Für diese Änderung wird kein Release automatisch veröffentlicht.

## Module

### Domainanalyse

- DNS: A, AAAA, NS, MX, TXT, SOA, CAA, jeweils mit TTL und Ergebnisstatus.
- Domainregistrierung: RDAP anhand des IANA-Verzeichnisses, einschließlich domainbezogener Registry-/Registrar-Verweise, Status und Datumsangaben. Antworten jeder Stufe bleiben erhalten.
- Klassische WHOIS-Kette: IANA → Registry → Registrar → weitere neue WHOIS-Verweise, mit vollständiger Abfragehistorie im Arbeitsspeicher und Rohdaten-Auszügen im Bericht.
- Netzwerkregistrierung: zuständiges RIR über das IANA-IP-Verzeichnis, bis zu drei öffentliche IPs, Netzbereich und veröffentlichte Betreiberangaben.
- TLS: geprüfter Hostname und System-Vertrauenskette, Gültigkeit, Aussteller, SAN-Domains, ausgehandeltes TLS/Cipher und SHA-256-Fingerabdruck des Serverzertifikats.
- HTTPS: HEAD-Anfrage, Status, Weiterleitungsziel und ausgewählte Antwort-/Sicherheitsheader. Weiterleitungen werden **nicht** verfolgt; keine Seiteninhalte oder Skripte geladen.

DNS ist immer aktiv. Die übrigen Bereiche sind einzeln abwählbar. Vor dem Start wird ein Abfrageplan erstellt. Das Ermitteln der RDAP-Dienste kann bereits öffentliche IANA-Verzeichnisse laden; das wird vor dem Plan-Button ausgewiesen. Der Plan zeigt die Domain-Registry und die möglichen RIR-Dienste vor der Zustimmung. Im Report sind die tatsächlich angefragten Quellen dokumentiert. Ein nicht verfügbarer Dienst wird ausdrücklich als nicht verfügbar ausgewiesen und gilt nicht als unauffälliges Ergebnis.

Externe Abfragen erhalten ein gemeinsames Zeitbudget (40 Sekunden für den Plan, 120 Sekunden für die Domainanalyse, 65 Sekunden für die Headeranalyse), zusätzlich zu den einzelnen DNS-, Verbindungs- und Antwortlimits. Bereits laufende Socketoperationen können noch bis zu ihrem kurzen Einzelzeitlimit auslaufen.

Dies ist **kein** vollständiger TLS-Schwachstellenscan, keine ASN-/BGP- oder Geolokalisierungsanalyse und keine eigenständige DNSSEC-/OCSP-/CRL-Prüfung. Die registrierbare Basisdomain wird für RDAP/WHOIS über den in `tldextract` mitgelieferten Public-Suffix-Snapshot ermittelt, etwa `mail.example.co.uk` → `example.co.uk`. Es gibt keinen Listendownload oder Dateicache zur Laufzeit. DNS, TLS und HTTPS untersuchen weiterhin die eingegebene Subdomain. Ist die Endung im Snapshot unbekannt, wird das ausgewiesen und die vollständige Eingabe verwendet.

### WHOIS- und RDAP-Abfrageketten

Die klassische Domain-WHOIS-Kette orientiert sich an der bewährten Implementierung aus [Forensic SiteSaver, domain_analysis.py](https://github.com/gl1tchb1rd/forensic_sitesaver/blob/c27b021a2500bbc7a499e4791129f536c3ee94c7/.forensic_sitesaver/domain_analysis.py) (GPL-3.0-or-later; Urheberhinweis im adaptierten Modul `forensics/whois.py`). Übernommen wurden insbesondere:

- IANA-Abfrage der registrierbaren Domain, bei fehlendem nutzbarem Verweis zusätzlicher TLD-Fallback.
- Tolerantes Erkennen von `refer`, `whois`, `Whois Server`, `Registrar WHOIS Server`, `Registry WHOIS Server`, `ReferralServer` und `Referral Server`, einschließlich Einrückungen, Tabs und Groß-/Kleinschreibung.
- VeriSign-/CRSNIC-Abfragen mit `dom`, `domain`, `=` und schließlich dem bloßen Domainnamen, soweit die vorherigen Antworten keine passenden Domaininformationen liefern. Transportfehler und erkennbare Abfragelimits lösen keine sinnlosen Syntax-Retries aus.
- Eine Warteschlange verfolgt alle neu genannten WHOIS-Dienste, auch nach dem Registrar und über verzweigte Verweise. Bereits abgefragte oder vorgemerkte Dienste werden nicht nochmals kontaktiert. Verweise aus früheren Antwortvarianten bleiben erhalten.
- Maximal acht weitere WHOIS-Server nach IANA. Das ist ein Sicherheitslimit, kein reguläres Kettenende. Offene Dienste, Zeit-/Größenlimits und Abfragefehler werden ausdrücklich als unvollständig ausgewiesen.

Bei `.de` endet die klassische WHOIS-Kette regulär bei DENIC; ein dort fehlender weiterer Registrar-Verweis ist nicht automatisch ein Fehler. Eine zusätzliche DENIC-WebWhois-Abfrage aus Sitesaver ist nicht Bestandteil dieser Änderung. Verdeckte oder nicht veröffentlichte Angaben werden durch die Kettenverfolgung nicht zugänglich.

Jede WHOIS-Anfrage wird im Browserbericht und PDF mit Dienst, tatsächlicher Query, UTC-Zeitpunkt, verweisendem Dienst, erkannten Folgediensten, empfangener Bytezahl und SHA-256 festgehalten. Rohdaten werden pro Antwort als Auszug von maximal 16.384 Zeichen mitgegeben; die Prüfsumme bezieht sich auf sämtliche tatsächlich empfangenen Bytes. Antworten sind auf 128 KiB plus ein Erkennungsbyte begrenzt. Bei Timeout oder Größenlimit bleibt die Teilantwort erhalten und wird als solche gekennzeichnet. Es gibt weiterhin keine Berichtsdateien, Datenbank oder Logs auf dem Server.

Domain-RDAP folgt zusätzlich HTTP-Weiterleitungen und `related`-Links für dieselbe registrierbare Domain über HTTPS/443. Keine Kontakt-/Entity-Abfragen, anderen Domains, zusätzlichen URL-Abfrageparameter oder anderen Protokolle. Maximal acht Abrufe einschließlich Weiterleitungen. Jede Antwort und deren Herkunft bleibt dokumentiert; ein nicht erreichbarer Registrar verwirft keine frühere Registry-Antwort. Die Netzbereichs-RDAP-Abfragen bleiben auf die im Plan ausgewiesenen RIR-Dienste beschränkt.

**Übermittelte Daten und Ziele:** Der Abfrageplan nennt IANA, die bekannte Registry und die Möglichkeit dynamischer Weiterverweise, bevor die Analyse beginnt. Die konkreten Folgedienste können erst aus deren Antworten bekannt werden. Die Zustimmung umfasst diese beschriebenen Referral-Abfragen. Übermittelt werden nur die registrierbare Domain bzw. TLD und feste Query-Präfixe, kein Aktenzeichen, E-Mail-Header, Cookie oder Anwendungspasswort. Alle tatsächlich abgefragten Dienste stehen im Bericht. WHOIS über TCP 43 ist unverschlüsselt; das ist in Eingabemaske und Abfrageplan ausgewiesen. Die WHOIS-Kette kann separat abgewählt werden.

**Betrieb:** Ausgehendes TCP 43 zu öffentlichen WHOIS-Diensten muss erlaubt sein. Bei einem Proxy muss HTTP CONNECT zu TCP 43 freigegeben sein. Optional kann `WF_WHOIS_PROXY` einen gesonderten HTTP-CONNECT-Proxy festlegen; sonst wird der vorhandene HTTPS-Proxy genutzt, sofern konfiguriert. Es erfolgt kein direkter Ausweichversuch bei einer Proxy-Ablehnung. Ohne Proxy wird direkt zur vorher geprüften, festgehaltenen öffentlichen IP verbunden. Private Ziele, Anmeldedaten in Referrals, andere Ports und Protokolle werden gesperrt. RWHOIS ist ein anderes Protokoll (typisch TCP 4321) und wird nicht stillschweigend als WHOIS/TCP 43 behandelt; ein solcher Verweis wird als nicht unterstützte, offene Stufe ausgewiesen. Anbieter können WHOIS eingestellt, eingeschränkt oder durch RDAP ersetzt haben; dies wird nicht als unauffälliger bzw. vollständig ermittelter Datensatz dargestellt.

### E-Mail-Header-Analyse

- Absenderfelder und Unterschiede zwischen From, Reply-To und Return-Path.
- Received-Stationen in behaupteter zeitlicher Reihenfolge, UTC-Zeitstempel und Zeitwidersprüche.
- Vorhandene Authentication-Results, ARC-Authentication-Results, Received-SPF und DKIM-Signature.
- IP-Adressen aus Received und X-Originating-IP, doppelte oder fehlende wichtige Felder und Parserfehler.
- Originaleingabe und deren SHA-256-Prüfsumme im Bericht.

Standardmäßig vollständig ohne externe Abfragen. Optional können maximal drei öffentliche Header-IP-Adressen mit Netzwerk-RDAP ergänzt werden; dafür ist ein bestätigter Abfrageplan erforderlich. Der vollständige Header wird nicht an diese Dienste gesendet. Nur Header einfügen, keine Nachrichtentexte oder Anhänge. Eingaben mit Nachrichtentext werden abgewiesen. Maximal 64 KiB UTF-8-Eingabe und 1500 Zeilen.

Eingetragene SPF-/DKIM-/DMARC-Ergebnisse sind **unverifizierte Behauptungen des Headers**. Die Anwendung kennt keine vertrauenswürdige Empfangsgrenze und bestätigt diese Ergebnisse nicht. Eine vollständige DKIM-Prüfung benötigt auch den Nachrichteninhalt. Received-Felder belegen keinen tatsächlichen Urheber oder Standort.

## Datenfluss und Grenzen der flüchtigen Verarbeitung

1. Eingaben werden ausschließlich per POST zur eigenen Installation übertragen, niemals als Suchparameter in URLs.
2. Der Server verarbeitet die Analyse im RAM und liefert Ergebnisse mit einem signierten, vollständigen Berichtspaket an die Browserseite zurück. Die Signatur schützt den PDF-Endpunkt vor manipulierten Berichtsdaten; sie ist keine digitale Beweissignatur und keine Verschlüsselung.
3. Der Server hält kein Untersuchungsarchiv und keinen Berichtcache. Nur öffentliche IANA-Anbieterlisten werden pro Prozess gecacht. Auf dem Server werden keine Eingaben oder Berichte als Dateien angelegt.
4. Beim PDF-Download sendet die Browserseite das Berichtspaket per POST an dieselbe Instanz. Das PDF entsteht in einem Speicherpuffer und wird direkt ausgeliefert.
5. Nach dem Start des Downloads sowie beim Verlassen der Ergebnisansicht werden die Formularfelder, Ergebnisse und das Berichtspaket aus der Browseransicht entfernt. Die Anwendung verwendet weder Local Storage noch IndexedDB oder einen Service Worker. Antworten tragen `Cache-Control: no-store`. Ein zufälliges CSRF-Cookie schützt POST-Anfragen und enthält keine Untersuchungsdaten.

PDF-Pakete sind maximal 30 Minuten gültig; Abfragepläne zehn Minuten. Der Signaturschlüssel entsteht beim Start einmal im Gunicorn-Masterprozess und wird mit `preload_app` an die Worker vererbt. Ein Neustart macht offene Berichte ungültig. Für mehrere unabhängig gestartete Replikate wäre ein gemeinsamer, zufälliger `WF_SECRET_KEY` erforderlich. Ein Single-Container-Betrieb benötigt keine Schlüsselkonfiguration.

Das Freigeben von Referenzen garantiert kein sofortiges Überschreiben sämtlicher RAM-Kopien. Browser/Erweiterungen, Host-Swap, Speicherabbilder, Hypervisoren, Reverse-Proxys und heruntergeladene Dateien kann die Anwendung nicht kontrollieren. Ein abgebrochener Browserrequest beendet laufende Netzwerkabfragen nicht zwingend sofort; diese sind begrenzt und speichern keine Ergebnisse. Ein gestarteter Download bestätigt nicht, dass der Benutzer die Datei tatsächlich gespeichert hat.

Anwendung und Gunicorn schreiben keine Zugriffs-, Fehler- oder Analyseprotokolle. Die mitgelieferte Compose-Datei deaktiviert zusätzlich den Docker-Logging-Treiber. Das betrifft den laufenden Dienst, nicht Paketinstallations- und Build-Ausgaben oder vom Betreiber zusätzlich eingesetzte Systeme.

## Externe Ziele

| Zweck | Empfänger | Übermittelte Daten |
| --- | --- | --- |
| DNS | Resolver aus Container-/Hostkonfiguration; rekursive Weitergabe möglich | Domain-/Dienstnamen, Recordtyp |
| Anbieterlisten | `data.iana.org/rdap/dns.json`, `ipv4.json`, `ipv6.json` | Keine Untersuchungsdaten; statische Verzeichnisabfrage |
| Domain-RDAP | Zuständige Registry und deren domainbezogene Registrar-RDAP-Verweise über HTTPS | Registrierbare Basisdomain |
| Klassische WHOIS-Kette | `whois.iana.org` und die daraufhin benannten öffentlichen WHOIS-Server, TCP 43 | Registrierbare Domain, gegebenenfalls TLD und feste VeriSign-Abfragepräfixe; unverschlüsselt |
| Netzwerk-RDAP | Zuständiges RIR laut Abfrageplan, z. B. ARIN/RIPE/APNIC/LACNIC/AFRINIC | Einzelne öffentliche IP-Adresse |
| TLS/HTTPS | Öffentliche IP der Zieldomain, Port 443 | SNI/Host, Standard-User-Agent und HEAD-Anfrage an `/` |
| Manuelle Release-Prüfung | `api.github.com` | Statische Abfrage des aktuellen öffentlichen Releases, ohne Untersuchungsdaten oder installierte Versionsnummer |

Alle externen Verbindungen offenbaren auch die Absender-IP der Installation bzw. des konfigurierten Proxys. Aktenzeichen und vollständige Header gehen nicht an diese Dienste. Eigene DNS-Resolver können über `WF_DNS_RESOLVERS` als kommagetrennte IPs festgelegt werden (in Compose bei Bedarf zusätzlich eintragen). Ausgehende DNS-Verbindungen und HTTPS müssen beim jeweiligen Betreiber erlaubt sein.

HTTPS respektiert konfigurierte `HTTPS_PROXY`-/`NO_PROXY`-Einstellungen und `SSL_CERT_FILE`. Für TLS-Proxys muss ein passendes, vertrauenswürdiges CA-Bundle schreibgeschützt eingebunden werden. Verifikation wird nicht abgeschaltet. HTTP-CONNECT-Proxys müssen Tunnel zu geprüften öffentlichen **IP-Adressen** erlauben; SNI und Zertifikatsprüfung verwenden weiter den ursprünglichen Hostnamen. Hostnamen-basierte Egress-Allowlists können dies einschränken. Die Anwendung wechselt in diesem Fall nicht auf einen unsicheren Verbindungspfad.

Private, lokale, reservierte und spezielle IPv6-Übergangsadressen werden für Zielverbindungen gesperrt. Gemischte öffentliche/private DNS-Antworten führen zur Sperre. Verbindungen verwenden die zuvor geprüfte IP, um DNS-Rebinding zwischen Prüfung und Verbindungsaufbau zu vermeiden. RDAP-Weiterleitungen sind auf im Plan ausgewiesene Anbieter beschränkt. Betreiber sollten ergänzend den Netzwerkzugriff des Containers auf interne Infrastruktur beschränken.

## Entwicklung und Tests

Python 3.12 oder neuer:

```sh
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python manage.py check
.venv/bin/python manage.py test tests
.venv/bin/gunicorn --config gunicorn.conf.py webforensics.wsgi:application
```

Keine Migrationen oder Datenbankeinrichtung nötig. `requirements.in` enthält die direkten, `requirements.txt` sämtliche festgeschriebenen Laufzeitabhängigkeiten. `requirements-dev.txt` ergänzt PDF- und Browsertestwerkzeuge. Der Entwicklungsstart nutzt ebenfalls die Gunicorn-Konfiguration ohne Logging; Djangos `runserver` ist für den zugesagten Betrieb ohne Zugriffslogs nicht vorgesehen.

Automatische Tests prüfen Offline-Verarbeitung, Headerbefunde, SSRF-Sperren, IP-Pinning/SNI, Abfragepläne, WHOIS-/RDAP-Ketten, VeriSign- und IANA-Fallbacks, Referral-Schleifen, Abbruchgründe, Redirect-Grenzen, Pflichtfelder, CSRF, Berichtsintegrität, PDF-Inhalte, Mehrseitenberichte und den optionalen Passwortschutz. Netzwerkantworten werden in den deterministischen Tests kontrolliert simuliert; das ist kein Nachweis der Verfügbarkeit aller externen Anbieter. Ein Browsertest gegen einen laufenden Dienst ist mit `tests/browser_smoke.py` möglich (System-Chromium oder `playwright install chromium` erforderlich). Bei aktiviertem Passwortschutz dafür `WF_TEST_AUTH_USERNAME` und `WF_TEST_AUTH_PASSWORD` in der Testumgebung setzen; die Werte werden nicht ausgegeben.

## Weitere Module ergänzen

Die Analysefunktionen sind von Oberfläche, HTTP-Endpunkten und PDF-Renderer getrennt. Neue Module können unter `forensics/` das gemeinsame Reportformat aus `forensics/report.py` verwenden. Anschließend Eingabevalidierung und Modulrouting in `webforensics/views.py`, eine Kachel/Eingabemaske in `templates/index.html` und die Bedienlogik in `static/app.js` ergänzen. Das Aktenzeichen wird zentral validiert; alle Module müssen Aussagegrenzen, Quellen und externe Empfänger dokumentieren. Der PDF-Renderer verarbeitet das gemeinsame Abschnittsformat.

## Lizenz und Betrieb

GPL-3.0 gemäß [LICENSE](LICENSE). Die Anwendung dient der technischen Dokumentation und liefert keine abschließende rechtliche Bewertung oder Garantie gerichtlicher Verwertbarkeit. Der Betreiber entscheidet über berechtigten Einsatz, Zugang, Serverstandort und die für seine Installation erforderlichen Datenschutzinformationen. Eine Lizenz oder ein Hinweis ersetzt keine technische Betriebskonfiguration.
