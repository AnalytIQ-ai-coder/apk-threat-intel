/*
    Dropper podszywajacy sie pod "TikTok18", ladujacy falszywy portfel MetaMask.

    PODSTAWA DOWODOWA: OSIEM PROBEK (3 z 2026-09-10, 4 z 2026-09-11, 1 wczesniej).
    Kazda ma INNY klucz podpisujacy, wiec osiem kluczy na osiem probek.
      b00c61bf  com.pc3f42aa3f.tiktok18  "TikTok18."  19/76  CN=main_app
      66c10f24  com.pc3a8529b9.tiktok18  "TikTok18."  17/76  CN=main_app
      e56cd724  com.pe08678163.tiktok18  "TikTok18+"  14/75  CN=main_app
      9d2ac3af  com.pca5dfe934.tiktok18  "TikTok18"   12/76  CN=App
      bde48eeb  com.pcdddf9a2d.tiktok18  "TikTok18"   15/76  CN=App
      70f49128  com.p8e4aa0f84.tiktok18  "TikTok18"   14/76  CN=App
      969a8667  com.pb27556682.tiktok18  "TikTok18"   14/74  CN=App
      b634c8c0  com.build.goog           —           10/75  CN=dog, BEZ payloadu

    Ostatnia pozycja jest tu wazna: ten sam builder, ale bez
    libmetamask_loader.so. Regula na certyfikat lapie ja mimo braku payloadu,
    a regula na payload lapie build podpisany kluczem spoza tego zestawu —
    dlatego sa OSOBNE i zadna nie jest nadzbiorem drugiej.

    UWAGA O ETYKIECIE — dlaczego "TikTok18" NIE jest tu kotwica:
    w bazie sa co najmniej cztery ROZNE klastry uzywajace tej samej przynety,
    kazdy z innym kluczem: "CN=Update Service", klucz testowy AOSP (dwie probki),
    "CN=APK Signer/OU=Earth" (patrz earth_signer.yar) oraz opisywany tutaj
    "CN=main_app". Dopasowanie po nazwie aplikacji zlepiloby je w jedno i
    zniszczylo rozroznienie miedzy kampaniami.

    CO JEST STALE:
      * podmiot certyfikatu "CN=main_app, O=Org, L=City, ST=State, C=RS" —
        pola L i ST doslownie brzmia "City" i "State", czyli sa NIEWYPELNIONA
        DOMYSLKA narzedzia. To ten sam typ artefaktu co "APK Signer/Earth"
        i "Venom Tools/New York City": identyfikuje BUILDER, nie operatora,
        bo dostanie go kazdy klient tego samego narzedzia.
      * trzy ROZNE klucze wystawione 9, 17 i 18 stycznia — builder generuje
        swiezy klucz do kazdego builda, wiec kotwica na module RSA zlapalaby
        jedna probke z trzech. Stad brak reguly na modul: przy per-build
        kluczu nie ma czego przypinac.
      * lib/{arm64-v8a,armeabi-v7a}/libmetamask_loader.so — identyczna nazwa
        we wszystkich trzech.
      * pakiet kodu "com.example.MetaMask" przy nazwie pakietu w manifescie
        "com.p<8 hex>.tiktok18" — nazwa pakietu zrandomizowana, pakiet kodu
        zostawiony z domyslnym prefiksem Android Studio. Ten sam blad co
        "com.nameown12" u Venoma. NIE DA SIE go jednak uzyc — patrz nizej.

    DLACZEGO CALA REGULA SIEDZI W PRZEBIEGU SUROWYM — zmierzone, i to jest
    tu najwazniejsze:
    wpisy tych APK maja ustawiony bit 0 flag ogolnych ZIP, czyli znacznik
    "wpis zaszyfrowany". Android to ignoruje i aplikacje instaluje, ale zipfile
    odmawia (RuntimeError "File is encrypted"). Zakres jest rozny per probka:
      b00c61bf  oznaczone classes.dex i AndroidManifest.xml,
      e56cd724  oznaczone WSZYSTKIE wpisy — bufor przebiegu po zawartosci
                jest calkowicie PUSTY.
    Skutkiem jest to, ze komponenty "com.example.MetaMask.*", widoczne dla
    androguarda (ma luzniejszy czytnik), sa dla skanera niedostepne. Kazda
    regula oparta na stringach z manifestu albo z DEX-a bylaby na tym klastrze
    martwa. Zostaja wylacznie: DER certyfikatu i nazwy wpisow ZIP — jedno
    i drugie w przebiegu po surowym pliku.
*/

rule MetaMask_Loader_Builder_Cert
{
    meta:
        description = "Builder dropperow z niewypelniona domyslka narzedzia w podmiocie certyfikatu (O=Org, L=City, ST=State) — przynety TikTok18 i inne"
        family = "MetaMask loader / builder RS"
        cert_subject = "CN=<zmienne>, O=Org, L=City, ST=State, C=RS"
        uwaga = "podmiot identyfikuje BUILDER, nie operatora — klucz jest generowany per build (8 roznych kluczy w 8 probkach)"
        samples_seen = 8
        distinct_certs = 8
        vt_range = "10-19 / 76"
        first_seen = "2026-09"
    strings:
        // Kotwice obejmuja OID atrybutu i naglowek lancucha, nie sam napis —
        // dzieki temu trafiaja wylacznie w strukture Name w DER.
        // 06 03 55 04 0a = OID 2.5.4.10 (organizationName), 13 03 = PrintableString(3)
        $o = { 06 03 55 04 0a 13 03 4f 72 67 }
        // 06 03 55 04 07 = OID 2.5.4.7 (localityName), 13 04 = PrintableString(4)
        $l = { 06 03 55 04 07 13 04 43 69 74 79 }
        // 06 03 55 04 08 = OID 2.5.4.8 (stateOrProvinceName), 13 05 = PrintableString(5)
        $st = { 06 03 55 04 08 13 05 53 74 61 74 65 }
    condition:
        // CN-a tu NIE MA i to jest poprawka po pomiarze, nie uproszczenie.
        // Pierwsza wersja reguly wymagala CN=main_app i przez to przepuscila
        // 5 z 8 probek klastra: w bazie sa TRZY warianty CN przy identycznej
        // reszcie podmiotu — "main_app" (3 probki), "App" (4), "dog" (1).
        // Zmienna czescia jest wiec CN, a stala komplet trzech niewypelnionych
        // domyslek narzedzia. Zmierzone na wszystkich osmiu probkach: bajty
        // $o, $l i $st sa w kazdej identyczne.
        //
        // Trzy naraz, bo kazdy z osobna jest zbyt pospolity — dopiero zestaw
        // "Org" + "City" + "State" w polach, ktore czlowiek wypelnilby
        // sensownie, jest sygnalem. W bazie 8 na 8 takich probek ma VT 10-19;
        // zadna nie jest czysta.
        all of them
}

rule MetaMask_Loader_Payload
{
    meta:
        description = "Biblioteka natywna libmetamask_loader.so — payload dropperow podszywajacych sie pod portfel MetaMask"
        family = "MetaMask loader"
        uwaga = "osobno od reguly na certyfikat, zeby zlapac tez build podpisany innym kluczem"
        samples_seen = 3
        first_seen = "2026-09"
    strings:
        $arm64 = "lib/arm64-v8a/libmetamask_loader.so" ascii
        $arm32 = "lib/armeabi-v7a/libmetamask_loader.so" ascii
    condition:
        // Nazwy wpisow ZIP z przebiegu po surowym pliku. Kazda wystepuje
        // dwukrotnie (naglowek lokalny + katalog centralny), ale wymog "any"
        // wystarczy: prawdziwy portfel MetaMask nie nazywa tak biblioteki.
        any of them
}

rule APK_Wpisy_Oznaczone_Jako_Zaszyfrowane
{
    meta:
        description = "Wpisy APK z ustawionym bitem 'zaszyfrowany' w flagach ZIP — Android je zignoruje i zainstaluje, narzedzia analityczne odmowia rozpakowania"
        technika = "ZIP encryption flag abuse"
        uwaga = "wykryte na klastrze tiktok18/MetaMask. Skutek dla tego repo: yara_scanner pomija taki wpis, wiec reguly na jego stringi cicho nie strzelaja (obsluzone komunikatem w _odkompresowana_zawartosc)"
        samples_seen = 3
        first_seen = "2026-09"
    strings:
        // Naglowek lokalny wpisu: sygnatura(4) wersja(2) FLAGI(2) metoda(2)
        // czas(2) data(2) crc(4) csize(4) usize(4) dlnazwy(2) dlextra(2),
        // nazwa od offsetu 30 — stad [26] miedzy sygnatura a nazwa.
        // Kotwiczymy na dwoch wpisach, ktore MUSZA istniec w kazdym APK.
        $lfh_manifest = { 50 4b 03 04 [26] 41 6e 64 72 6f 69 64 4d 61 6e 69 66 65 73 74 2e 78 6d 6c }
        $lfh_dex = { 50 4b 03 04 [26] 63 6c 61 73 73 65 73 2e 64 65 78 }
    condition:
        // Bit 0 flag ogolnych (offset +6 od sygnatury) oznacza "zaszyfrowany".
        // W poprawnym APK nie ma prawa byc ustawiony: Android nie obsluguje
        // szyfrowania ZIP, wiec jedynym powodem ustawienia go jest zmylenie
        // narzedzi, ktore ten bit respektuja.
        for any i in (1..#lfh_manifest) : ( uint16(@lfh_manifest[i] + 6) & 1 == 1 )
        or for any i in (1..#lfh_dex) : ( uint16(@lfh_dex[i] + 6) & 1 == 1 )
}
