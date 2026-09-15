rule NFC_Card_Relay
{
    meta:
        description = "NFC relay: the sample both READS a payment card and EMULATES one"
        family = "NFC relay (NGate-like)"
        first_seen = "2026-08"
        lure = "Cartao Protegido / card verification - the victim taps a card against the phone"
        confidence = "needs verification: a legitimate banking wallet can also have both halves"
    strings:
        // reading a physical card
        $read_isodep     = "IsoDep" ascii
        $read_transceive = "transceive" ascii
        $read_mode       = "enableReaderMode" ascii
        // card emulation (the receiving end of the relay)
        $emu_hce         = "HostApduService" ascii
        $emu_apdu        = "processCommandApdu" ascii
        // the contactless payment directory AID - code that talks to EMV cards
        $ppse            = "2PAY.SYS.DDF01" ascii
    condition:
        // Reading alone can be legitimate (wallets, document readers), and so
        // can emulation alone (HCE in a bank's own app). Only both halves at
        // once describe a relay. PPSE raises confidence that payment cards are
        // what this is about.
        ((any of ($read_*)) and (any of ($emu_*)))
        or ($ppse and (any of ($emu_*)))
}

rule NFC_Payment_Card_Reader
{
    meta:
        description = "Sample queries the contactless payment directory (PPSE) - it reads EMV cards"
        family = "NFC / EMV"
        confidence = "an indicator, not a verdict: legitimate wallets and payment terminals do this too"
    strings:
        $ppse = "2PAY.SYS.DDF01" ascii
        $ppse_alt = "1PAY.SYS.DDF01" ascii
    condition:
        any of them
}
