/*
    Kampania "rentaapps" / System_Upgrade — dropper z C2 pod bsqzx.xyz.

    13 probek, 12 roznych nazw pakietu (ghy.<trzy litery>.rentaapps),
    wszystkie o nazwie aplikacji "System_Upgrade", VT 8-18/75, etykieta
    "dropper". Kazda probka ma DOKLADNIE JEDNA biblioteke natywna o entropii
    ~7.996 (czyli zaszyfrowana, nie tylko spakowana) pod losowa nazwa:
    libearth.so, libflag.so, libempty.so, libbench.so, libbot.so...
    Randomizacja nazwy pliku jest tu swiadomym unikiem, wiec regula NIE moze
    sie o nia opierac.

    DLACZEGO NIE PO KLUCZU PODPISUJACYM (inaczej niz campaign_certs.yar):
    caly klaster jest podpisany kluczem testowym AOSP
    (SHA-1 27196E386B875E76ADF700E7EA84E4C6EEE33DFA). Ten klucz jest PUBLICZNY
    — lezy w drzewie zrodel Androida i uzywa go kazdy, kto buduje z testkey.
    W naszej wlasnej bazie ten sam klucz maja cztery niepowiazane rodziny
    (com.liquidity.sweeps.core, DIXMAX TV, net.nccjus.kedkgbv, teuq.lbnn.zzo),
    czyli 5 z 18 probek to NIE jest ta kampania. Kotwica na module RSA dalaby
    tu bledna atrybucje i trafiala w dowolny build testowy Androida.

    Kotwiczymy wiec na C2 i na odcisku buildera.
*/

rule Rentaapps_C2_bsqzx
{
    meta:
        description = "Dropper 'System_Upgrade' z rodziny rentaapps — C2 bsqzx.xyz, pakiet ghy.<xxx>.rentaapps, jedna zaszyfrowana biblioteka natywna o losowej nazwie"
        family = "rentaapps / bsqzx.xyz"
        c2 = "bsqzx.xyz"
        samples_seen = 13
        distinct_packages = 12
        vt_range = "8-18 / 75"
        cert_note = "klucz testowy AOSP 27196E386B875E76 — WSPOLDZIELONY, nie nadaje sie na kotwice"
        first_seen = "2026-09"
    strings:
        $c2      = "bsqzx.xyz" ascii
        $pkg_dot = "rentaapps" ascii
        $prov    = "com.launcher.mango.LauncherProvider" ascii
        $prov_l  = "Lcom/launcher/mango/LauncherProvider" ascii
        $label   = "System_Upgrade" ascii
    condition:
        // Wylacznie znane C2. Domena nie wystepuje nigdzie poza ta kampania,
        // wiec samo jej trafienie jest wystarczajaca przeslanka.
        // Odcisk buildera bez C2 obsluguje ODDZIELNA regula ponizej — gdyby
        // byl tu jako galaz OR, tamta nigdy by nie strzelila.
        $c2 and any of ($pkg_dot, $prov, $prov_l, $label)
}

rule Rentaapps_Builder_Nowa_Domena
{
    meta:
        description = "Sam odcisk buildera rentaapps bez znanego C2 — prawdopodobna nowa fala z rotowana domena"
        family = "rentaapps (builder)"
        samples_seen = 13
        first_seen = "2026-09"
    strings:
        $pkg_dot = "rentaapps" ascii
        $label   = "System_Upgrade" ascii
        $prov    = "com.launcher.mango" ascii
        $prov_l  = "Lcom/launcher/mango" ascii
        $c2      = "bsqzx.xyz" ascii
    condition:
        // Celowo "not $c2": ta regula ma lapac wylacznie to, czego pierwsza
        // juz nie zlapala, zeby trafienie znaczylo "nowa domena, sprawdz ja".
        not $c2 and $pkg_dot and $label and any of ($prov, $prov_l)
}
