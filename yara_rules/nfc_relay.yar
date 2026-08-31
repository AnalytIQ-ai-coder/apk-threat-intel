rule NFC_Card_Relay
{
    meta:
        description = "Przekaznik NFC: probka jednoczesnie CZYTA karte platnicza i EMULUJE karte"
        family = "NFC relay (NGate-podobne)"
        first_seen = "2026-08"
        lure = "Cartao Protegido / weryfikacja karty — ofiara przyklada karte do telefonu"
        confidence = "wymaga weryfikacji: legalny portfel bankowy tez moze miec obie strony"
    strings:
        // odczyt fizycznej karty
        $read_isodep     = "IsoDep" ascii
        $read_transceive = "transceive" ascii
        $read_mode       = "enableReaderMode" ascii
        // emulacja karty (strona odbiorcza przekaznika)
        $emu_hce         = "HostApduService" ascii
        $emu_apdu        = "processCommandApdu" ascii
        // AID katalogu platnosci zblizeniowych — kod gadajacy z kartami EMV
        $ppse            = "2PAY.SYS.DDF01" ascii
    condition:
        // Sam odczyt bywa legalny (portfele, czytniki dokumentow), sama emulacja
        // tez (HCE w aplikacji banku). Dopiero obie strony naraz opisuja
        // przekaznik. PPSE podnosi pewnosc, ze chodzi o karty platnicze.
        ((any of ($read_*)) and (any of ($emu_*)))
        or ($ppse and (any of ($emu_*)))
}

rule NFC_Payment_Card_Reader
{
    meta:
        description = "Probka odpytuje katalog platnosci zblizeniowych (PPSE) — czyta karty EMV"
        family = "NFC / EMV"
        confidence = "wskaznik, nie werdykt: uzywaja tego rowniez legalne portfele"
    strings:
        $ppse = "2PAY.SYS.DDF01" ascii
        $ppse_alt = "1PAY.SYS.DDF01" ascii
    condition:
        any of them
}
