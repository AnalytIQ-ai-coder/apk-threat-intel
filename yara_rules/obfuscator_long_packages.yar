/*
    The package-naming template of one APK obfuscator.

    This is a rule about a TOOL, not a family - and that only emerged from
    measurement, because it was written as a companion to crypto_stealer.yar.

    MEASURED REACH: eleven samples across THREE different keystores, so at
    least three operators bought or stole the same obfuscator:
      5D08264B  fiscal.cry, whh.premium, examined.fy, dating.cst,
                generate.developers, build.ledear.nwmfj        18-30 / 75
      B79DF4A8  codes.stuart.tuner "CraxsApp", faqs.area.conspiracy
                "5G+ Updater", observed.groups.sectors "APK DONE",
                supervision.bikes.prophet "BanProtect"          11-26 / 75
      C2393994  com.centres.cycling "Telegram"                  29 / 75

    What they share is the Telegram client source run through this obfuscator.
    The families differ (crypto stealer, RAT, updater), so a hit here says
    "built with this tool" and NOT "same campaign". Distinguishing campaigns is
    what the family rules are for.

    WHAT EXACTLY IS RECOGNISED: the obfuscator names packages with 40-60 random
    lower-case letters and appends a digit that grows with nesting depth (2 for
    the parent package, 3/4/5 for sub-packages). That digit matters - without
    it the rule would catch ordinary long names.

    ON THE THRESHOLD: the match count is set from measurement, not from taste.
    Across 16 controls of clean software (Nagram X, AyuGram, Rarevision VHS,
    ReVanced Manager, Monefy Pro, 100 Floors, APKPure with the qihoo packer and
    10 random VT 0 samples from the database) the count is ZERO - not "low",
    zero. Across the eleven positives it runs from 472 to 1791. The two sets do
    not overlap at all, so a threshold of 20 is safe with enormous margin.

    Separately measured controls that do NOT match despite the resemblance:
      com.appd.instll.load and supervision - same B79DF4A8 keystore,
      com.example.reverseshell2 and com.yszt.xgj - same 5D08264B keystore.
    So not everything leaving those machines goes through this obfuscator.
*/

rule Obfuscator_Long_Packages_With_Depth_Digit
{
    meta:
        description = "Obfuscator naming packages with 40-60 random lower-case letters plus a nesting-depth digit - a tool shared by several operators"
        family = "obfuscator (a tool, not a family)"
        note = "a hit means 'built with this tool', not 'same campaign' - measured across 3 different keystores"
        samples_seen = 11
        distinct_certs = 3
        vt_range = "11-30 / 75"
        first_seen = "2026-09"
    strings:
        // DEX type descriptor: L<package>/<...>. Two short segments before the
        // long one, so a long class name sitting shallow is not picked up.
        $template = /L[a-z][a-z0-9_]{1,15}\/[a-z][a-z0-9_]{1,15}\/[a-z]{40,60}[2-9]\//
    condition:
        // Measured separation: 0 across 16 controls, 472-1791 across positives.
        #template >= 20
}
