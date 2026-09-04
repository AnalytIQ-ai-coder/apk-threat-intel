/*
    Klaster podpisany kluczem "CN=APK Signer, OU=Earth, O=Earth"
    (SHA-1 517955EABF69FC057C41C7D379DBBCEF20AD85F2, waznosc 2019-09-03 -> 2049-10-25).

    W bazie cztery probki, wszystkie zlosliwe, VT 12-19/75, etykieta trojan.locker:
      mq0bt5.jv6ar0.gimh45ww7     "VIDEO"      19/75
      cr2892y07l.kfhx31.vk8f0yw   "MAX_VIDE0"  16/75
      es.loom.linen               "TikTok18+"  12/75
      com.ukolfh.kfrcaespe        "RASMLAR"    12/75

    UWAGA O KLUCZU — inaczej niz w bsqzx_rentaapps.yar, gdzie kotwica na kluczu
    byla wykluczona, tu klucz JEST uzyty, ale swiadomie tylko jako polowa
    warunku. Powod ostroznosci: "APK Signer / Earth / Earth" wyglada na domyslny
    podmiot z jakiegos narzedzia do podpisywania APK, a nie na dane wpisane
    przez operatora. Jesli tak jest, klucz moze byc wspoldzielony przez
    niepowiazane osoby dokladnie tak, jak klucze testowe AOSP. Cztery probki to
    za malo, zeby to rozstrzygnac, wiec regula glowna wymaga DODATKOWO odcisku
    buildera, a sam klucz obsluguje osobna regula oznaczona jako hunting.

    ODCISK BUILDERA (zmierzony na VIDEO i MAX_VIDE0; RASMLAR go NIE ma):
      * ~52 wpisow ZIP uzywa zarezerwowanych nazw APK jako KATALOGOW:
        "classes.dex/....jpg", "AndroidManifest.xml/..xml", "resources.arsc/...xml".
        Zaden legalny build tak nie wyglada — to unik na naiwne rozpakowywarki
        i analizatory szukajace tych nazw.
      * classes.dex i resources.arsc sa zapisane bez kompresji (STORED),
        AndroidManifest.xml jest zdeflatowany.
      * uprawnienia o losowych nazwach zaczynajacych sie OD CYFRY
        ("android.permission.1TKPV12F", "android.permission.9VSJXV44O0").
        Zadne prawdziwe uprawnienie Androida nie zaczyna sie cyfra.
      * jeden content provider o nazwie zlozonej z homoglifow mieszanych
        alfabetow (grecki + cyrylica + CJK + arabski) — losowany per probka,
        wiec NIE nadaje sie na kotwice.
      * nazwa aplikacji z doklejonym U+200B ("VIDEO​") — lamie dopasowanie
        po dokladnej etykiecie.

    GDZIE TE CIAGI SA WIDOCZNE — i dlaczego rozbicie na cztery reguly:
    yara_scanner robi DWA OSOBNE przebiegi: rules.match(sciezka) po surowych
    bajtach i rules.match(data=...) po rozpakowanej zawartosci. To znaczy, ze
    JEDNA REGULA NIE MOZE LACZYC CIAGU Z JEDNEGO PRZEBIEGU Z CIAGIEM Z DRUGIEGO
    — warunek nigdy nie bedzie spelniony i regula po cichu nie strzeli.
      * podmiot certyfikatu i nazwy wpisow ZIP -> tylko przebieg SUROWY,
      * stringi z AndroidManifest.xml (UTF-16, stad "wide") i z classes.dex
        -> tylko przebieg po ROZPAKOWANEJ zawartosci.
    Pierwsza wersja tego pliku laczyla certyfikat z uprawnieniami w jednym
    warunku; test test_earth_same_uprawnienia_utf16_wystarczaja pokazal, ze ta
    galaz jest martwa. Dlatego marker manifestu stoi w osobnej regule.
*/

rule Earth_Signer_Wabiki_ZIP
{
    meta:
        description = "Trojan.locker podpisany kluczem 'APK Signer/Earth' — ZIP z zarezerwowanymi nazwami APK jako katalogami i uprawnieniami o nazwach od cyfry"
        family = "APK Signer / Earth"
        cert_sha1 = "517955EABF69FC057C41C7D379DBBCEF20AD85F2"
        samples_seen = 4
        builder_confirmed_on = 2
        vt_range = "12-19 / 75"
        first_seen = "2026-09"
    strings:
        // Fragment DER podmiotu: OU=Earth (55 04 0b) tuz przed CN=APK Signer (55 04 03).
        $cert_dn = { 04 0b 0c 05 45 61 72 74 68 31 13 30 11 06 03 55 04 03 0c 0a 41 50 4b 20 53 69 67 6e 65 72 }
        // Zarezerwowane nazwy APK uzyte jako katalog — ukosnik jest tu istotny,
        // bo prawdziwe wpisy nazywaja sie "classes.dex" bez niego.
        $wabik_dex      = "classes.dex/" ascii
        $wabik_manifest = "AndroidManifest.xml/" ascii
        $wabik_arsc     = "resources.arsc/" ascii
    condition:
        // Oba ciagi pochodza z przebiegu po surowych bajtach — patrz naglowek.
        // Kilka wabikow, a nie jeden: pojedyncze trafienie moze byc przypadkiem
        // w danych binarnych, kilkadziesiat juz nie.
        $cert_dn and (#wabik_dex > 3 or #wabik_manifest > 3 or #wabik_arsc > 3)
}

rule Earth_Signer_Klucz_Hunting
{
    meta:
        description = "Ten sam klucz podpisujacy 'APK Signer/Earth' bez odcisku buildera — inna galaz kampanii albo wspoldzielony klucz domyslny, wymaga potwierdzenia"
        family = "APK Signer / Earth (hunting)"
        cert_sha1 = "517955EABF69FC057C41C7D379DBBCEF20AD85F2"
        uwaga = "podmiot moze byc domyslka narzedzia do podpisywania — traktowac jako przeslanke, nie atrybucje"
        first_seen = "2026-09"
    strings:
        $cert_dn = { 04 0b 0c 05 45 61 72 74 68 31 13 30 11 06 03 55 04 03 0c 0a 41 50 4b 20 53 69 67 6e 65 72 }
        // notBefore 190903230324Z / notAfter 491025230324Z — przypina do
        // konkretnego certyfikatu, nie tylko do tej samej nazwy podmiotu.
        $waznosc = { 30 1e 17 0d 31 39 30 39 30 33 32 33 30 33 32 34 5a 17 0d 34 39 31 30 32 35 32 33 30 33 32 34 5a }
        $wabik_dex      = "classes.dex/" ascii
        $wabik_manifest = "AndroidManifest.xml/" ascii
        $wabik_arsc     = "resources.arsc/" ascii
    condition:
        // "not" celowo: probki, ktore lapie regula wyzej, maja zostac tam.
        // Trafienie TUTAJ ma znaczyc "ten sam klucz, ale inny build — sprawdz".
        // Markera z manifestu nie da sie tu uzyc: w przebiegu po surowych
        // bajtach jest niewidoczny, wiec warunek na niego bylby atrapa.
        $cert_dn and $waznosc
        and not (#wabik_dex > 3 or #wabik_manifest > 3 or #wabik_arsc > 3)
}

rule APK_Zarezerwowane_Nazwy_Jako_Katalogi
{
    meta:
        description = "APK uzywa 'classes.dex', 'AndroidManifest.xml' lub 'resources.arsc' jako nazw katalogow — unik strukturalny, niezalezny od rodziny"
        technika = "ZIP structure confusion"
        uwaga = "podstawa dowodowa waska: 2 probki pozytywne, 3 negatywne. Zadne znane narzedzie budujace nie tworzy katalogu o takiej nazwie, ale przy pierwszych trafieniach warto sprawdzic recznie."
        first_seen = "2026-09"
    strings:
        $wabik_dex      = "classes.dex/" ascii
        $wabik_manifest = "AndroidManifest.xml/" ascii
        $wabik_arsc     = "resources.arsc/" ascii
    condition:
        // Dwie rozne zarezerwowane nazwy uzyte jako katalog i lacznie duzo wpisow.
        2 of them and (#wabik_dex + #wabik_manifest + #wabik_arsc) > 10
}

rule APK_Uprawnienia_O_Nazwach_Od_Cyfry
{
    meta:
        description = "Manifest deklaruje uprawnienia o losowych nazwach zaczynajacych sie od cyfry — zaden prawdziwy identyfikator uprawnienia Androida tak nie wyglada"
        technika = "manifest noise / obfuskacja uprawnien"
        uwaga = "dziala w przebiegu po ROZPAKOWANEJ zawartosci, bo pula stringow AXML jest zdeflatowana i zakodowana UTF-16"
        first_seen = "2026-09"
    strings:
        // Zmierzone na probkach VIDEO (3 sztuki) i MAX_VIDE0 (4 sztuki).
        // Cyfra na poczatku jest tu calym sygnalem: nazwy uprawnien Androida
        // sa identyfikatorami w stylu odwroconego DNS i nigdy nie zaczynaja
        // sie cyfra, wiec nie ma tu ryzyka kolizji z czyms prawdziwym.
        $perm_od_cyfry = /android\.permission\.[0-9][A-Z0-9]{4,}/ wide
    condition:
        #perm_od_cyfry >= 2
}
