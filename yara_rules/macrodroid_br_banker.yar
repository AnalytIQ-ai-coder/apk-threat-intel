/*
    MacroDroid repacked into a Brazilian banking trojan - one operator.

    EVIDENCE BASE: FIVE SAMPLES, all declaring package com.arlosoft.macrodroid
    (the real automation app) and all carrying the same build fingerprint:

      ff6b7e5f  "Lanterna Potente"   14/75   2026-09-14
      5be608a5  "Rei dos Canais"     26/74   2026-09-15
      0199bca9  "Lanterna Potente"   15/75   2026-09-25
      9e4d11fc  "kikinoia"           20/75   2026-09-25
      ffd0c7ae  "Gov"                13/75   2026-09-25

    Five different app labels, one build: versionName is byte-for-byte
    "96.94.51 chlmcnqnshwqbfopi" in all five, as is the target list and the
    C2. Only the label and the icon change between drops, which is why the
    label is useless as an anchor and the version string is not.

    The payload rides on real MacroDroid: the app's own automation engine
    provides the accessibility plumbing (AccessibilityService,
    performGlobalAction, findAccessibilityNodeInfosByText), SMS send/receive
    and DeviceAdminReceiver, so the operator adds only a target list and a
    callback. That is also why static analysis looks so ordinary - almost
    every dangerous API here belongs to the legitimate app.

    WHAT IS NOT HERE, AND WHY.

    No rule on the signing certificate. All five carry the AOSP test key
    (SHA1 61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81), which covers 103 samples
    in output/threat_intel.db - Bloons TD 6, ibisPaint X, Vine, CraxsRat,
    NordVPN clones, Iranian banking lures. It identifies a build made with
    publicly available keys and nothing else. Measured and rejected.

    No rule on the bank URLs alone. Every Brazilian banking trojan lists the
    same handful of institutions, so on their own they would describe the
    target country rather than this operator. They are kept only as the
    second half of a pair, to survive a C2 rotation.

    No rule on the package name com.arlosoft.macrodroid: the real app shares
    it, and a rule that fires on the genuine application is worse than no rule.

    MEASUREMENT (in memory, mirroring yara_scanner._decompressed_content):
    every string below appears in 5 of 5 cluster samples and in 0 of 25
    controls - the most recent non-split samples in the database, clean and
    malicious mixed.

    ENCODING - the detail that decides whether this file works at all. The
    version string lives in the binary AndroidManifest.xml, where AXML stores
    it as UTF-16LE. As ASCII it matches 0 of 5; as "wide" it matches 5 of 5.
    The C2 and the URLs come from the DEX and are ASCII. Both entries are in
    the CONTENT pass (rules.match(data=...)), so the rule is internally
    consistent - but note that a build using the ZIP tricks from
    venom_tools.yar or metamask_loader.yar would empty that buffer and this
    rule would silently fail, as every content-pass rule would.
*/

rule MacroDroid_Repack_BR_Banker
{
    meta:
        description = "MacroDroid repacked as a Brazilian banking trojan - one build relabelled across drops, C2 179.0.179.195:5000"
        family = "MacroDroid repack / BR banker"
        note = "rides on the real app's automation engine, so the dangerous APIs belong to MacroDroid itself"
        c2 = "179.0.179.195:5000"
        samples_seen = 5
        vt_range = "13-26 / 75"
        first_seen = "2026-09"
    strings:
        // The operator's build fingerprint: a real versionName followed by a
        // random 17-letter suffix. UTF-16LE because it comes out of the binary
        // manifest - see the note on encoding above.
        $version = "96.94.51 chlmcnqnshwqbfopi" wide

        // The callback. An IP with an explicit port in a DEX is not something
        // a legitimate build carries, which is why this half stands alone.
        $c2 = "179.0.179.195:5000" ascii

        // The target list. Weak on its own, decisive next to the version.
        $bank_caixa     = "https://internetbanking.caixa.gov.br" ascii
        $bank_nubank    = "https://nubank.com.br" ascii
        $bank_itau      = "https://www.itau.com.br" ascii
        $bank_santander = "https://www.santander.com.br" ascii
        $bank_bradesco  = "https://www.banco.bradesco" ascii
    condition:
        // Either half is enough, and they fail in different directions.
        // The C2 dies the day the operator moves host; the version string
        // dies the day they rebuild. Requiring both would lose the cluster
        // at the first change to either.
        //
        // Three banks rather than all five: the list has already varied in
        // length across other BR bankers, and demanding the full set makes
        // the rule brittle for nothing - three of these five in one file is
        // not something an honest app does.
        $c2 or ($version and 3 of ($bank_*))
}
