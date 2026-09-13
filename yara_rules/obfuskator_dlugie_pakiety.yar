/*
    Szablon nazw pakietow pewnego obfuskatora APK.

    To regula na NARZEDZIE, nie na rodzine — i wyszlo to dopiero z pomiaru,
    bo pisalem ja jako uzupelnienie krypto_stealer.yar.

    ZMIERZONY ZASIEG: jedenascie probek, TRZY ROZNE keystore'y, czyli co
    najmniej trzech operatorow kupilo albo ukradlo ten sam obfuskator:
      5D08264B  fiscal.cry, whh.premium, examined.fy, dating.cst,
                generate.developers, build.ledear.nwmfj        18-30 / 75
      B79DF4A8  codes.stuart.tuner "CraxsApp", faqs.area.conspiracy
                "5G+ Updater", observed.groups.sectors "APK DONE",
                supervision.bikes.prophet "BanProtect"          11-26 / 75
      C2393994  com.centres.cycling "Telegram"                  29 / 75

    Wspolnym mianownikiem jest kod bazowy klienta Telegrama przepuszczony
    przez ten obfuskator. Rodziny sa rozne (kradziejca krypto, RAT, updater),
    wiec trafienie tej reguly mowi "zbudowane tym narzedziem", a NIE
    "to ta sama kampania". Do rozroznienia kampanii sluza reguly rodzinowe.

    CO DOKLADNIE ROZPOZNAJEMY: obfuskator nadaje pakietom nazwy z 40-60
    losowych malych liter, a na koncu dokleja cyfre rosnaca z glebokoscia
    zagniezdzenia (2 dla pakietu nadrzednego, 3/4/5 dla podpakietow). Ta
    cyfra jest tu istotna — bez niej regula lapalaby zwykle dlugie nazwy.

    ROZDZIAL OD MIARY WIELKOSCI: prog liczby trafien jest ustawiony
    z pomiaru, nie z oka. Na 16 kontrolach czystego oprogramowania
    (Nagram X, AyuGram, Rarevision VHS, ReVanced Manager, Monefy Pro,
    100 Floors, APKPure z pakerem qihoo i 10 losowych probek VT 0 z bazy)
    liczba trafien wynosi ZERO — nie "mало", tylko zero. Na jedenastu
    probkach pozytywnych: od 472 do 1791. Miedzy tymi zbiorami nie ma
    czesci wspolnej, wiec prog 20 jest bezpieczny z ogromnym zapasem.

    Osobno zmierzone kontrole, ktore NIE trafiaja mimo podobienstwa:
      com.appd.instll.load i supervision — ten sam keystore B79DF4A8,
      com.example.reverseshell2 i com.yszt.xgj — ten sam keystore 5D08264B.
    Czyli nie wszystko, co wychodzi z tych maszyn, idzie przez ten obfuskator.
*/

rule Obfuskator_Dlugie_Pakiety_Z_Cyfra_Glebokosci
{
    meta:
        description = "Obfuskator nadajacy pakietom 40-60 losowych malych liter z cyfra glebokosci zagniezdzenia na koncu — narzedzie dzielone przez kilku operatorow"
        family = "obfuskator (narzedzie, nie rodzina)"
        uwaga = "trafienie mowi 'zbudowane tym narzedziem', nie 'ta sama kampania' — zmierzone na 3 roznych keystorach"
        samples_seen = 11
        distinct_certs = 3
        vt_range = "11-30 / 75"
        first_seen = "2026-09"
    strings:
        // Deskryptor typu w DEX: L<pakiet>/<...>. Dwa krotkie czlony przed
        // czlonem dlugim, zeby nie lapac dlugiej nazwy klasy lezacej plytko.
        $szablon = /L[a-z][a-z0-9_]{1,15}\/[a-z][a-z0-9_]{1,15}\/[a-z]{40,60}[2-9]\//
    condition:
        // Zmierzony rozdzial: 0 na 16 kontrolach, 472-1791 na pozytywach.
        #szablon >= 20
}
