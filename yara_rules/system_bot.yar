/*
    Rodzina RAT-ow o etykiecie aplikacji "System", z payloadem w libbot.so.

    PODSTAWA DOWODOWA: CZTERY PROBKI, wszystkie zmierzone, nie zalozone.
      5a615846  com.google.classroom   32/75  2026-09-10  cert 8642E3B3 (debug)
      4c05e3e8  com.chingusapk.juan    30/75  2026-09-03  cert A6F47B26 (debug)
      50b7a48d  com.chingusapk.juan    28/75  2026-08-30  cert 395CA6C0 (debug)
      e46d5e32  com.juan.art           32/75  2026-08-31  cert 61ED377E (testkey AOSP)

    CO JEST STALE, A CO SIE ZMIENIA — to rozstrzyga o wyborze kotwicy:
      zmienia sie   nazwa pakietu (trzy rozne), certyfikat (cztery rozne),
                    infrastruktura C2 (juan.art ma inna niz pozostale trzy),
      NIE zmienia sie  komplet 16 nazw komponentow — IDENTYCZNY we wszystkich
                    czterech probkach — oraz nazwa biblioteki natywnej libbot.so.

    Dlatego kotwica NIE jest ani na kluczu, ani na domenach C2. Klucz jest
    rotowany co build (trzy keystore'y debugowe plus raz klucz testowy AOSP),
    a domeny wymieniono miedzy 08-31 a 09-03. Zestaw komponentow przezyl jedno
    i drugie.

    DLACZEGO DOMENY C2 SA TU BEZUZYTECZNE JAKO STRING — sprawdzone:
    "cnc.control-panel-live.net", "mgmt-panel.serverstats-daemon.com" i
    "sync.softwaremirror.workers.dev" widnieja w bazie jako IOC tej probki, ale
    NIE WYSTEPUJA doslownie ani w classes.dex, ani w surowych bajtach APK.
    Ekstraktor wydobyl je inna droga (dekodowanie), wiec regula na nie
    nie mialaby na czym strzelic. Zostaja w bazie jako IOC, nie jako kotwica.

    ZDOLNOSCI, ktore ten zestaw komponentow oznacza — stad dobor progu:
      TrustAgentService   utrzymanie urzadzenia w stanie odblokowanym,
      IMEService          wlasna klawiatura, czyli keylogger z definicji,
      NotificationService odczyt wszystkich powiadomien, czyli kodow OTP,
      AccessibilityService klikanie za uzytkownika,
      AdminReceiver       device admin (blokada, wipe),
      SecretCodeReceiver  aktywacja kodem MMI wybranym na klawiaturze telefonu,
      DreamService, QSTileService, PersistService  utrzymanie sie przy zyciu.
    Zadna zwykla aplikacja nie deklaruje tej czworki naraz.

    PRZEBIEGI SKANERA (patrz naglowek earth_signer.yar — ciag z jednego przebiegu
    nie moze stac w warunku razem z ciagiem z drugiego):
      * nazwy komponentow  -> przebieg po ZAWARTOSCI. Sa w dwoch miejscach:
        w puli stringow AndroidManifest.xml (UTF-16, stad "wide") i jako
        deskryptory klas w classes.dex (ASCII). Obie formy zmierzone.
      * nazwy wpisow ZIP (lib/.../libbot.so) -> przebieg SUROWY.
*/

rule System_Bot_Zestaw_Komponentow
{
    meta:
        description = "RAT z etykieta 'System': trust agent + wlasna klawiatura + czytnik powiadomien + accessibility w jednym manifescie"
        family = "System / libbot"
        samples_seen = 4
        distinct_packages = 3
        distinct_certs = 4
        vt_range = "28-32 / 75"
        first_seen = "2026-08"
    strings:
        // Nazwy PROSTE, bez pakietu: nazwa pakietu jest losowana per build
        // (com.google.classroom / com.chingusapk.juan / com.juan.art), wiec
        // deskryptor z pelna sciezka nie bylby stabilny.
        $kyorij = "KyorijService" ascii wide
        $trust = "TrustAgentService" ascii wide
        $ime = "IMEService" ascii wide
        $qs = "QSTileService" ascii wide
        $dream = "DreamService" ascii wide
        $secret = "SecretCodeReceiver" ascii wide
        $persist = "PersistService" ascii wide
        $admin = "AdminReceiver" ascii wide
        $restart = "RestartReceiver" ascii wide
        $netrec = "NetworkReceiver" ascii wide
        $pkgrec = "PackageReceiver" ascii wide
    condition:
        // "KyorijService" to slowo bez znaczenia i nie wystepuje nigdzie indziej
        // w korpusie — samo w sobie jest mocna kotwica. Dokladamy do niego trzy
        // dowolne markery zdolnosci, zeby pojedyncze trafienie w danych
        // binarnych nie wystarczylo.
        ($kyorij and 3 of ($trust, $ime, $qs, $dream, $secret, $persist))
        // Galaz zapasowa na wypadek, gdyby "Kyorij" bylo losowane w kolejnych
        // buildach: wtedy nosnikiem sygnalu jest sam ZESTAW. Prog 8 z 10 jest
        // wysoki celowo — pojedyncze nazwy w rodzaju AdminReceiver czy
        // DreamService wystepuja w zwyklych aplikacjach.
        or 8 of ($trust, $ime, $qs, $dream, $secret, $persist, $admin, $restart, $netrec, $pkgrec)
}

rule System_Bot_libbot
{
    meta:
        description = "Biblioteka natywna nazwana libbot.so obok wariantow libbot32/libbot64 — payload rodziny 'System'"
        family = "System / libbot"
        uwaga = "dziala w przebiegu SUROWYM: to nazwy wpisow ZIP, ktore w katalogu centralnym leza otwartym tekstem"
        samples_seen = 4
        first_seen = "2026-08"
    strings:
        // Sciezka razem z katalogiem ABI, zeby nie trafic w slowo "libbot"
        // wystepujace przypadkiem w danych binarnych.
        $arm64 = "lib/arm64-v8a/libbot" ascii
        $arm32 = "lib/armeabi-v7a/libbot" ascii
        $x86 = "lib/x86/libbot" ascii
    condition:
        // Co najmniej dwie architektury: pojedyncza sciezka to za malo,
        // a wszystkie cztery probki maja komplet arm64 + armeabi-v7a + x86.
        2 of them
}
