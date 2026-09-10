/*
    Klaster podpisany kluczem "CN=Venom Tools, OU=Software, O=Venom Software,
    L=New York City, ST=New York, C=US"
    (SHA-1 936E0ACB069D912BE4FF6D10B5E799460719EBB6, RSA-2048, podpis v2,
    waznosc 2024-08-22 -> 2052-01-08).

    PODSTAWA DOWODOWA: JEDNA PROBKA. To mniej niz przy earth_signer.yar (cztery)
    i za malo, zeby odroznic odcisk BUILDERA od artefaktu POJEDYNCZEGO BUILDU.
    Cala struktura ponizej jest tym podyktowana: kotwice sa rozdzielone wedlug
    tego, jak bardzo ryzykuja, zamiast byc zlepione w jeden warunek.

      2ab4d9d01e2fd395aba7df5f3aec59b4899b0fc5f3295b55cd0d6664b010b285
      com.sgakagak.agakagabs, etykieta "Chrome", 26/75 na VT, 300 kB, 14 wpisow ZIP

    DLACZEGO PODMIOT CERTYFIKATU JEST TU UZYWANY, A W bsqzx_rentaapps.yar NIE:
    "Venom Software" to nazwa handlowa sprzedawcy RAT-ow, a pole L wypelnione
    "New York City" ma wygladac wiarygodnie, nie jest tym, co operator wpisuje
    sam dla siebie. To sklada sie na DOMYSLNY PODMIOT WPISANY W BUILDER — ta sama
    sytuacja co "APK Signer/Earth". Konsekwencja: sam podmiot NIE JEST atrybucja
    do operatora, bo kazdy klient tego samego narzedzia dostanie ten sam napis.
    Dlatego:
      * regula na MODUL KLUCZA przypina konkretna pare kluczy -> jeden operator,
      * regula na PODMIOT z wykluczeniem tego modulu lapie INNEGO klienta tego
        samego buildera -> sygnal do polowania, nie atrybucja.

    ODCISK KODU (zmierzony na tej jednej probce):
      * manifest deklaruje pakiet "com.sgakagak.agakagabs", ale WSZYSTKIE klasy
        siedza w "com.nameown12". Rozjazd jest istotny: nazwa pakietu zostala
        zrandomizowana, a pakiet kodu nie — czyli "nameown12" to najpewniej staly
        szablon buildera. Najpewniej, bo przy n=1 to nadal hipoteza.
      * klasy nazwane SLOWAMI KLUCZOWYMI Javy: Lfddo/break;, Lfddo/case;,
        Lfddo/catch;, Lfddo/const;, Lfddo/goto;, Lfddo/new;, Lfddo/super;,
        Lfddo/this;, Lfddo/try;. W DEX to legalne, w zrodle Javy nie — wiec
        dekompilator albo wypluje kod, ktorego nie da sie skompilowac, albo sie
        wywroci. Sam czlon "fddo" moze byc losowany per build, dlatego regula
        dopasowuje WZORZEC (dowolny krotki pakiet + slowo kluczowe), nie ten napis.
      * uprawnienia device-admina w res/xml/: wipe-data, reset-password,
        force-lock, disable-camera, watch-login, expire-password — pelny zestaw
        lacznie z kasowaniem danych. Do reguly sie NIE nadaje, bo res/xml/*.xml
        nie trafia do zadnego z dwoch przebiegow skanera (patrz nizej).
      * accessibility-service z canPerformGestures — synteza dotkniec, czyli
        zdolnosc klikania za uzytkownika.

    PRZEBIEGI SKANERA — dlaczego to pieć regul, a nie jedna:
    yara_scanner skanuje najpierw surowy plik, potem OSOBNO sklejone
    odkompresowane wpisy (.dex, .arsc, .so, AndroidManifest.xml, assets/).
    Ciag z jednego przebiegu nie moze stac w warunku razem z ciagiem z drugiego,
    bo taka galaz nigdy nie strzeli — na tym przewrocil sie pierwszy earth_signer.yar.
      * DER certyfikatu (blok podpisu v2)         -> przebieg SUROWY,
      * deskryptory klas z classes.dex            -> przebieg po ZAWARTOSCI,
      * nazwy wpisow ZIP (lib/.../libvixt.so)     -> przebieg SUROWY.
    Nazwy "libvixt.so" swiadomie NIE ma w zadnym warunku: przy jednej probce nie
    da sie odroznic stalej nazwy payloadu od losowanej per build, a rodzina
    rentaapps z tej samej bazy losuje ja za kazdym razem (libluggage, libdove,
    libhorror, libsharp...). Zostaje tu jako obserwacja do sprawdzenia przy
    drugiej probce.

    PODMIENIONA METODA KOMPRESJI MANIFESTU — zmierzone, nie zalozone:
    AndroidManifest.xml tej probki ma metode kompresji 17180 w central directory
    i 32040 w naglowku lokalnym. Obie sa nieprawidlowe (ZIP zna 0, 8, 9, 12, 14)
    i, co samo w sobie mowiace, ROZNE od siebie. Praktyczne skutki sa dwa:
      * zipfile Pythona rzuca NotImplementedError, wiec _odkompresowana_zawartosc
        w yara_scanner POMIJA ten wpis — kazda regula opierajaca sie na stringach
        z manifestu jest na tej probce SLEPA i nikt sie o tym nie dowie, bo
        wyjatek jest polykany. Dotyczy to m.in. APK_Uprawnienia_O_Nazwach_Od_Cyfry
        z earth_signer.yar.
      * androguard ma luzniejszy dekoder i manifest czyta bez problemu, wiec
        analiza statyczna widzi komplet 30 uprawnien. Rozjazd miedzy tym, co widzi
        parser, a tym, co widzi skaner regul, jest tu calym sednem techniki.
    Dlatego $pkg_axml trafia w przebiegu SUROWYM, a nie po zawartosci: strumien
    manifestu zawiera dlugie literalne fragmenty, wiec napisy UTF-16 leza w pliku
    otwartym tekstem. To wlasciwosc tego konkretnego pliku, nie regula ogolna —
    tym, co niesie dopasowanie niezaleznie od manifestu, jest $pkg_dex.
*/

rule Venom_Tools_Klucz_Operatora
{
    meta:
        description = "APK podpisany konkretnym kluczem buildera Venom Software - trojan SMS/accessibility z pelnym device-adminem, podszywa sie pod Chrome"
        family = "Venom Software"
        cert_sha1 = "936E0ACB069D912BE4FF6D10B5E799460719EBB6"
        cert_subject = "CN=Venom Tools, OU=Software, O=Venom Software, L=New York City"
        key = "RSA-2048, schemat podpisu v2"
        samples_seen = 1
        vt = "26 / 75"
        first_seen = "2026-09"
    strings:
        // Fragment modulu RSA (bajty 16-48), tak samo jak w campaign_certs.yar.
        // Modul jest unikalny dla pary kluczy, wiec przypina operatora,
        // a nie sam produkt.
        $modulus = { c5 fd 29 98 06 ed 61 3b c4 cf 2e 4a f2 8b 7c ad ec 89 14 f9 68 48 e2 62 2e 8a 8f 1c ea 21 cd 1a }
    condition:
        $modulus
}

rule Venom_Tools_Builder_Inny_Klucz
{
    meta:
        description = "Podmiot certyfikatu Venom Software przy INNYM kluczu niz znany - kolejny klient tego samego buildera, wymaga potwierdzenia"
        family = "Venom Software (hunting)"
        uwaga = "podmiot jest domyslka narzedzia, wiec dzieli go kazdy klient - przeslanka co do buildera, nie atrybucja operatora"
        first_seen = "2026-09"
    strings:
        // Kotwice obejmuja OID atrybutu i naglowek PrintableString, nie sam
        // napis: dzieki temu trafiaja wylacznie w strukture Name w DER, a nie
        // w slowo "Venom Tools" lezace gdziekolwiek indziej w pliku.
        // 06 03 55 04 03 = OID 2.5.4.3 (commonName), 13 0b = PrintableString(11)
        $dn_cn = { 06 03 55 04 03 13 0b 56 65 6e 6f 6d 20 54 6f 6f 6c 73 }
        // 06 03 55 04 0a = OID 2.5.4.10 (organizationName), 13 0e = PrintableString(14)
        $dn_o = { 06 03 55 04 0a 13 0e 56 65 6e 6f 6d 20 53 6f 66 74 77 61 72 65 }
        $modulus = { c5 fd 29 98 06 ed 61 3b c4 cf 2e 4a f2 8b 7c ad ec 89 14 f9 68 48 e2 62 2e 8a 8f 1c ea 21 cd 1a }
    condition:
        // Oba atrybuty naraz, zeby przypadkowa organizacja o nazwie "Venom
        // Software" nie wystarczyla. "not $modulus" celowo: probka ze znanym
        // kluczem ma zostac zlapana przez regule wyzej, a trafienie TUTAJ ma
        // znaczyc "ten builder, ale nowy klucz - sprawdz recznie".
        $dn_cn and $dn_o and not $modulus
}

rule Venom_Tools_Pakiet_Kodu_nameown12
{
    meta:
        description = "Klasy w pakiecie com.nameown12 przy innej nazwie pakietu w manifescie - nieprzemianowany szablon buildera Venom Software"
        family = "Venom Software"
        uwaga = "hipoteza z jednej probki: nazwa pakietu w manifescie byla zrandomizowana, pakiet kodu nie. Drugie trafienie potwierdzi albo obali."
        first_seen = "2026-09"
    strings:
        // Deskryptor typu z classes.dex.
        $pkg_dex = "com/nameown12/" ascii
        // Ta sama nazwa w puli stringow AndroidManifest.xml - AXML trzyma je
        // w UTF-16, stad "wide". Manifest tez idzie do przebiegu po zawartosci.
        $pkg_axml = "com.nameown12" wide
    condition:
        any of them
}

rule Obfuskator_Klasy_O_Nazwach_Slow_Kluczowych
{
    meta:
        description = "DEX zawiera klasy nazwane slowami kluczowymi Javy (break, const, goto, catch...) - legalne w bajtkodzie, niekompilowalne w zrodle, wiec lamie dekompilatory"
        technika = "anti-decompilation / keyword class naming"
        uwaga = "podstawa dowodowa waska - patrz naglowek pliku. Prog 6 roznych slow ma odsiac pojedyncze przypadkowe trafienie w danych binarnych."
        first_seen = "2026-09"
    strings:
        // Deskryptor typu DEX: "L" + krotki pakiet + "/" + slowo kluczowe + ";".
        // Pakiet jest wzorcem, nie stalym napisem, bo czlon "fddo" z jedynej
        // znanej probki moze byc losowany per build.
        $kw_break = /L[a-z]{2,10}\/break;/ ascii
        $kw_case = /L[a-z]{2,10}\/case;/ ascii
        $kw_catch = /L[a-z]{2,10}\/catch;/ ascii
        $kw_class = /L[a-z]{2,10}\/class;/ ascii
        $kw_const = /L[a-z]{2,10}\/const;/ ascii
        $kw_else = /L[a-z]{2,10}\/else;/ ascii
        $kw_final = /L[a-z]{2,10}\/final;/ ascii
        $kw_goto = /L[a-z]{2,10}\/goto;/ ascii
        $kw_new = /L[a-z]{2,10}\/new;/ ascii
        $kw_super = /L[a-z]{2,10}\/super;/ ascii
        $kw_this = /L[a-z]{2,10}\/this;/ ascii
        $kw_try = /L[a-z]{2,10}\/try;/ ascii
    condition:
        // Dziala w przebiegu po ODKOMPRESOWANEJ zawartosci - classes.dex jest
        // zdeflatowany, wiec w przebiegu po surowym pliku tych ciagow nie ma.
        6 of them
}

rule APK_Manifest_Podmieniona_Metoda_Kompresji
{
    meta:
        description = "AndroidManifest.xml zadeklarowany z nieprawidlowa metoda kompresji ZIP - Android go otworzy, standardowe narzedzia analityczne nie"
        technika = "ZIP compression method confusion"
        uwaga = "wykryte przy probce Venom (metoda 17180 w central directory, 32040 w naglowku lokalnym). 1 probka pozytywna, 6 negatywnych."
        skutek = "yara_scanner polyka NotImplementedError i pomija manifest, wiec reguly na stringi z manifestu cicho nie strzelaja"
        first_seen = "2026-09"
    strings:
        // Naglowek lokalny wpisu ZIP, po ktorym od razu idzie nazwa pliku:
        // sygnatura(4) wersja(2) flagi(2) metoda(2) czas(2) data(2) crc(4)
        // csize(4) usize(4) dlnazwy(2) dlextra(2) = nazwa na offsecie 30.
        // Stad [26] miedzy sygnatura a nazwa.
        $lfh_manifest = { 50 4b 03 04 [26] 41 6e 64 72 6f 69 64 4d 61 6e 69 66 65 73 74 2e 78 6d 6c }
    condition:
        // Konkretnej wartosci NIE zaszywamy - przy jednej probce nie wiadomo,
        // czy builder ja losuje. Zamiast tego czytamy pole metody wprost
        // (offset +8 od sygnatury) i odrzucamy dwie jedyne, ktore w APK maja
        // sens: 0 (STORED) i 8 (DEFLATE). Reszta to albo unik, albo plik
        // uszkodzony - jedno i drugie warte spojrzenia.
        for any i in (1..#lfh_manifest) : (
            uint16(@lfh_manifest[i] + 8) != 0 and uint16(@lfh_manifest[i] + 8) != 8
        )
}
