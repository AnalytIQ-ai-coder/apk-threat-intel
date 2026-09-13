/*
    Kradziejca portfeli krypto — jedna partia buildow z keystora 5D08264B.

    PODSTAWA DOWODOWA: PIEC PROBEK, wszystkie podpisane tym samym debugowym
    kluczem Android Studio (SHA1 5D08264B44E0E53FBCCC70B4F016474CC6C5AB5C):
      adbc9ae4  com.fiscal.cry            "aaa" (cyrylica)   19/75
      14048b5c  com.whh.premium           "zzz" (cyrylica)   21/75
      84fe4bdd  com.examined.fy           "Blockchain"       18/75
      96cc7d4c  com.dating.cst            "Blockchain"       30/75
      ca0a1e74  com.generate.developers   "Anonim"           19/75
    Wszystkie zbudowane na kodzie zrodlowym klienta Telegrama i deklaruja
    com.wallet.crypto.trustapp jako cel.

    CZEGO TU NIE MA I DLACZEGO — to najwazniejsza czesc tego pliku.

    Trzy kandydujace kotwice ODRZUCONE po pomiarze w output/threat_intel.db:
      * static-maps.yandex.ru — 19 probek, w tym CZTERY czyste klienty
        Telegrama (Nagram, Nagram X, exteraless, Niagram X; VT 0) oraz
        AyuGram (VT 1). Artefakt kodu bazowego, nie sygnal.
      * telegram.org — 24 probki, ta sama kontaminacja.
      * www.blockchain.com — 4 trafienia, wszystkie na tym keystorze, ale to
        jeden pospolity string i brakuje go w com.whh.premium (4 z 5 probek).

    Nie ma tez reguly na sam keystore 5D08264B, mimo ze jest kuszacy: ma
    w bazie 27 probek o calkowitym rozrzucie rodzin — reverse shell, phishing
    Blockchain, klon Roblox, klon Niagara Launcher, Divar (IR), BNL (IT),
    chinskie narzedzie do automatyzacji. To odcisk MASZYNY deweloperskiej
    jednego aktora, nie rodziny; regula na niego zlepilaby te kampanie w
    jedna. Potwierdzenie z walidacji: com.yszt.xgj i com.example.reverseshell2
    maja ten sam keystore i ponizsza regula ich NIE lapie — i tak ma byc.

    CO ZOSTALO: nazwy pakietow wypluwane przez obfuskator. Struktura jest
    identyczna we wszystkich pieciu probkach:

        com/<czlon z nazwy pakietu>/<50 malych liter>2
            |-- <50 malych liter>3
            |-- <50 malych liter>4
            \-- <50 malych liter>5

    Czterem probkom (fiscal, examined, dating, generate) obfuskator wygenerowal
    DOKLADNIE te same czlony, co do bajtu — to jedna partia buildow. Piata,
    com.whh.premium, ma je przelosowane i lapie ja regula na sam szablon
    w obfuskator_dlugie_pakiety.yar.

    Stringi sa w DEX, czyli w przebiegu po ZAWARTOSCI (rules.match(data=...)).
    Wpisy tych probek sa normalnie skompresowane — zadna nie wymaga obejscia
    z venom_tools.yar ani metamask_loader.yar.
*/

rule Kradziejca_Krypto_Wspolny_Seed_Obfuskatora
{
    meta:
        description = "Kradziejca portfeli krypto — cztery buildy z jednego przebiegu obfuskatora, nazwy pakietow identyczne co do bajtu"
        family = "krypto stealer / keystore 5D08264B"
        uwaga = "celuje w com.wallet.crypto.trustapp; piata probka klastra ma przelosowany seed i lapie ja regula na szablon"
        cert_sha1 = "5D08264B44E0E53FBCCC70B4F016474CC6C5AB5C"
        samples_seen = 4
        vt_range = "18-30 / 75"
        first_seen = "2026-09"
    strings:
        // Piecdziesiat losowych malych liter — szansa na przypadkowa kolizje
        // jest zerowa, wiec nie trzeba tu zadnego kontekstu skladniowego.
        $p2 = "vhasjbytsejmchjytybqaiucxsovcftvkngegomeqdvgmgvqzg2" ascii
        $p3 = "lrnkvbkuoyhwwjjclyatabmdqjrxgnnkcjvzuleormlwhiwnjt3" ascii
        $p4 = "ymohvcbrknsnxeoujrdhblrwadynhwynfqzklncagrzgjnbnxk4" ascii
        $p5 = "ajfzohvjgwjouuagessauzaxzxmirruovuzkddzvvswwcyyfte5" ascii
    condition:
        // Pakiet nadrzedny plus dwa z trzech podpakietow. Wymog kompletu
        // bylby kruchy, gdyby ktorys build nie uzyl jednej z galezi.
        $p2 and 2 of ($p3, $p4, $p5)
}
