/*
    Crypto wallet stealer - one batch of builds from the 5D08264B keystore.

    EVIDENCE BASE: FIVE SAMPLES, all signed with the same Android Studio debug
    key (SHA1 5D08264B44E0E53FBCCC70B4F016474CC6C5AB5C):
      adbc9ae4  com.fiscal.cry            "aaa" (Cyrillic)   19/75
      14048b5c  com.whh.premium           "zzz" (Cyrillic)   21/75
      84fe4bdd  com.examined.fy           "Blockchain"       18/75
      96cc7d4c  com.dating.cst            "Blockchain"       30/75
      ca0a1e74  com.generate.developers   "Anonim"           19/75
    All are built on the Telegram client source and declare
    com.wallet.crypto.trustapp as a target.

    WHAT IS NOT HERE, AND WHY - the most important part of this file.

    Three candidate anchors REJECTED after measuring output/threat_intel.db:
      * static-maps.yandex.ru - 19 samples, including FOUR clean Telegram
        clients (Nagram, Nagram X, exteraless, Niagram X; VT 0) and AyuGram
        (VT 1). An artefact of the base code, not a signal.
      * telegram.org - 24 samples, same contamination.
      * www.blockchain.com - 4 hits, all on this keystore, but it is a single
        common string and com.whh.premium does not even have it (4 of 5).

    There is also no rule on the 5D08264B keystore itself, tempting as it is:
    it covers 27 samples with a completely scattered set of families - reverse
    shell, Blockchain phishing, a Roblox clone, a Niagara Launcher clone, Divar
    (IR), BNL (IT), a Chinese automation tool. That fingerprints one actor's
    MACHINE, not a family, and a rule on it would fuse those campaigns into
    one. Confirmed during validation: com.yszt.xgj and
    com.example.reverseshell2 share the keystore and the rule below does NOT
    catch them - which is exactly right.

    WHAT SURVIVED: the package names the obfuscator emits. The structure is
    identical across all five samples:

        com/<segment from the package name>/<50 lower-case letters>2
            |-- <50 lower-case letters>3
            |-- <50 lower-case letters>4
            \-- <50 lower-case letters>5

    For four of them (fiscal, examined, dating, generate) the obfuscator
    produced byte-for-byte identical segments - one batch of builds. The fifth,
    com.whh.premium, has them re-randomised and is caught by the template rule
    in obfuscator_long_packages.yar instead.

    The strings live in the DEX, i.e. the CONTENT pass (rules.match(data=...)).
    These samples' entries are normally compressed - none of them needs the
    workarounds from venom_tools.yar or metamask_loader.yar.
*/

rule Crypto_Stealer_Shared_Obfuscator_Seed
{
    meta:
        description = "Crypto wallet stealer - four builds from one obfuscator run, package names identical byte for byte"
        family = "crypto stealer / keystore 5D08264B"
        note = "targets com.wallet.crypto.trustapp; the cluster's fifth sample has a re-randomised seed and is caught by the template rule"
        cert_sha1 = "5D08264B44E0E53FBCCC70B4F016474CC6C5AB5C"
        samples_seen = 4
        vt_range = "18-30 / 75"
        first_seen = "2026-09"
    strings:
        // Fifty random lower-case letters: the chance of an accidental
        // collision is nil, so no syntactic context is needed around them.
        $p2 = "vhasjbytsejmchjytybqaiucxsovcftvkngegomeqdvgmgvqzg2" ascii
        $p3 = "lrnkvbkuoyhwwjjclyatabmdqjrxgnnkcjvzuleormlwhiwnjt3" ascii
        $p4 = "ymohvcbrknsnxeoujrdhblrwadynhwynfqzklncagrzgjnbnxk4" ascii
        $p5 = "ajfzohvjgwjouuagessauzaxzxmirruovuzkddzvvswwcyyfte5" ascii
    condition:
        // Parent package plus two of the three sub-packages. Demanding the
        // full set would be brittle if some build skipped one branch.
        $p2 and 2 of ($p3, $p4, $p5)
}
