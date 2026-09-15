/*
    Cluster signed with the key "CN=APK Signer, OU=Earth, O=Earth"
    (SHA-1 517955EABF69FC057C41C7D379DBBCEF20AD85F2, valid 2019-09-03 -> 2049-10-25).

    Four samples in the database, all malicious, VT 12-19/75, tagged trojan.locker:
      mq0bt5.jv6ar0.gimh45ww7     "VIDEO"      19/75
      cr2892y07l.kfhx31.vk8f0yw   "MAX_VIDE0"  16/75
      es.loom.linen               "TikTok18+"  12/75
      com.ukolfh.kfrcaespe        "RASMLAR"    12/75

    A NOTE ON THE KEY - unlike bsqzx_rentaapps.yar, where a key anchor was
    ruled out, here the key IS used, but deliberately only as half of the
    condition. The reason for caution: "APK Signer / Earth / Earth" looks like
    the default subject of some APK signing tool rather than anything an
    operator typed. If that is what it is, the key can be shared by unrelated
    people in exactly the way the AOSP test keys are. Four samples is too few
    to settle it, so the main rule ALSO requires the builder fingerprint, and
    the key on its own is handled by a separate rule marked as hunting.

    THE BUILDER FINGERPRINT (measured on VIDEO and MAX_VIDE0; RASMLAR does NOT
    have it):
      * ~52 ZIP entries use reserved APK names as DIRECTORIES:
        "classes.dex/....jpg", "AndroidManifest.xml/..xml", "resources.arsc/...xml".
        No legitimate build looks like this - it is an evasion aimed at naive
        unpackers and at analysers looking for those names.
      * classes.dex and resources.arsc are stored uncompressed (STORED), while
        AndroidManifest.xml is deflated.
      * permissions with random names STARTING WITH A DIGIT
        ("android.permission.1TKPV12F", "android.permission.9VSJXV44O0").
        No real Android permission starts with a digit.
      * one content provider whose name is built from homoglyphs across mixed
        alphabets (Greek + Cyrillic + CJK + Arabic) - randomised per sample, so
        NOT usable as an anchor.
      * an app label with a trailing U+200B ("VIDEO") - which breaks matching
        on the exact label.

    WHERE THESE STRINGS ARE VISIBLE - and why this is split into four rules:
    yara_scanner runs TWO SEPARATE passes: rules.match(path) over the raw bytes
    and rules.match(data=...) over the decompressed content. Which means ONE
    RULE CANNOT COMBINE A STRING FROM ONE PASS WITH A STRING FROM THE OTHER -
    the condition would never be satisfied and the rule would quietly never
    fire.
      * certificate subject and ZIP entry names -> RAW pass only,
      * strings from AndroidManifest.xml (UTF-16, hence "wide") and from
        classes.dex -> DECOMPRESSED-content pass only.
    The first version of this file combined the certificate with the
    permissions in one condition; the test for the UTF-16 permission marker
    showed that branch was dead. Hence the manifest marker lives in its own
    rule.
*/

rule Earth_Signer_ZIP_Lures
{
    meta:
        description = "Trojan.locker signed with the 'APK Signer/Earth' key - a ZIP using reserved APK names as directories and permissions named with a leading digit"
        family = "APK Signer / Earth"
        cert_sha1 = "517955EABF69FC057C41C7D379DBBCEF20AD85F2"
        samples_seen = 4
        builder_confirmed_on = 2
        vt_range = "12-19 / 75"
        first_seen = "2026-09"
    strings:
        // Subject DER fragment: OU=Earth (55 04 0b) right before CN=APK Signer (55 04 03).
        $cert_dn = { 04 0b 0c 05 45 61 72 74 68 31 13 30 11 06 03 55 04 03 0c 0a 41 50 4b 20 53 69 67 6e 65 72 }
        // Reserved APK names used as a directory - the slash matters here,
        // because genuine entries are called "classes.dex" without one.
        $lure_dex      = "classes.dex/" ascii
        $lure_manifest = "AndroidManifest.xml/" ascii
        $lure_arsc     = "resources.arsc/" ascii
    condition:
        // Both strings come from the raw-bytes pass - see the header.
        // Several lures rather than one: a single hit could be a coincidence
        // in binary data, several dozen could not.
        $cert_dn and (#lure_dex > 3 or #lure_manifest > 3 or #lure_arsc > 3)
}

rule Earth_Signer_Key_Hunting
{
    meta:
        description = "The same 'APK Signer/Earth' signing key without the builder fingerprint - another branch of the campaign, or a shared default key; needs confirmation"
        family = "APK Signer / Earth (hunting)"
        cert_sha1 = "517955EABF69FC057C41C7D379DBBCEF20AD85F2"
        note = "the subject may be a signing tool's default - treat as a lead, not as attribution"
        first_seen = "2026-09"
    strings:
        $cert_dn = { 04 0b 0c 05 45 61 72 74 68 31 13 30 11 06 03 55 04 03 0c 0a 41 50 4b 20 53 69 67 6e 65 72 }
        // notBefore 190903230324Z / notAfter 491025230324Z - pins this to one
        // specific certificate rather than merely to the same subject name.
        $validity = { 30 1e 17 0d 31 39 30 39 30 33 32 33 30 33 32 34 5a 17 0d 34 39 31 30 32 35 32 33 30 33 32 34 5a }
        $lure_dex      = "classes.dex/" ascii
        $lure_manifest = "AndroidManifest.xml/" ascii
        $lure_arsc     = "resources.arsc/" ascii
    condition:
        // The "not" is deliberate: samples the rule above catches should stay
        // there. A hit HERE should mean "same key, different build - go look".
        // The manifest marker cannot be used here: it is invisible in the raw
        // pass, so a condition on it would be a decoy.
        $cert_dn and $validity
        and not (#lure_dex > 3 or #lure_manifest > 3 or #lure_arsc > 3)
}

rule APK_Reserved_Names_As_Directories
{
    meta:
        description = "APK uses 'classes.dex', 'AndroidManifest.xml' or 'resources.arsc' as directory names - a structural evasion, independent of family"
        technique = "ZIP structure confusion"
        note = "narrow evidence base: 2 positive samples, 3 negative. No known build tool creates a directory with such a name, but the first few hits are worth checking by hand."
        first_seen = "2026-09"
    strings:
        $lure_dex      = "classes.dex/" ascii
        $lure_manifest = "AndroidManifest.xml/" ascii
        $lure_arsc     = "resources.arsc/" ascii
    condition:
        // Two different reserved names used as directories, and many entries overall.
        2 of them and (#lure_dex + #lure_manifest + #lure_arsc) > 10
}

rule APK_Permissions_Named_With_Leading_Digit
{
    meta:
        description = "Manifest declares permissions with random names starting with a digit - no real Android permission identifier looks like that"
        technique = "manifest noise / permission obfuscation"
        note = "works in the DECOMPRESSED-content pass, because the AXML string pool is deflated and UTF-16 encoded"
        first_seen = "2026-09"
    strings:
        // Measured on the VIDEO sample (3 of them) and MAX_VIDE0 (4 of them).
        // The leading digit is the entire signal here: Android permission
        // names are reverse-DNS style identifiers and never start with a
        // digit, so there is no risk of colliding with something real.
        $perm_leading_digit = /android\.permission\.[0-9][A-Z0-9]{4,}/ wide
    condition:
        #perm_leading_digit >= 2
}
