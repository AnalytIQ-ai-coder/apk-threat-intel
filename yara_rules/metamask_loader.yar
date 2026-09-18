/*
    Dropper posing as "TikTok18", loading a fake MetaMask wallet.

    EVIDENCE BASE: EIGHT SAMPLES (3 from 2026-09-10, 4 from 2026-09-11, 1
    earlier). Each has a DIFFERENT signing key, so eight keys for eight samples.
      b00c61bf  com.pc3f42aa3f.tiktok18  "TikTok18."  19/76  CN=main_app
      66c10f24  com.pc3a8529b9.tiktok18  "TikTok18."  17/76  CN=main_app
      e56cd724  com.pe08678163.tiktok18  "TikTok18+"  14/75  CN=main_app
      9d2ac3af  com.pca5dfe934.tiktok18  "TikTok18"   12/76  CN=App
      bde48eeb  com.pcdddf9a2d.tiktok18  "TikTok18"   15/76  CN=App
      70f49128  com.p8e4aa0f84.tiktok18  "TikTok18"   14/76  CN=App
      969a8667  com.pb27556682.tiktok18  "TikTok18"   14/74  CN=App
      b634c8c0  com.build.goog           -            10/75  CN=dog, NO payload

    That last entry matters here: same builder, but without
    libmetamask_loader.so. The certificate rule catches it despite the missing
    payload, and the payload rule catches a build signed with a key outside
    this set - which is why they are SEPARATE and neither is a superset of the
    other.

    A NOTE ON THE LABEL - why "TikTok18" is NOT an anchor here:
    the database holds at least four DIFFERENT clusters using the same lure,
    each with its own key: "CN=Update Service", the AOSP test key (two
    samples), "CN=APK Signer/OU=Earth" (see earth_signer.yar) and the
    "CN=main_app" family described here. Matching on the app label would fuse
    them into one and destroy the distinction between campaigns.

    WHAT IS CONSTANT:
      * the certificate subject "CN=<varies>, O=Org, L=City, ST=State, C=RS" -
        the L and ST fields literally read "City" and "State", i.e. they are
        UNFILLED TOOL DEFAULTS. Same class of artefact as "APK Signer/Earth"
        and "Venom Tools/New York City": it identifies the BUILDER, not the
        operator, because every customer of the same tool gets it.
      * three DIFFERENT keys issued on the 9th, 17th and 18th - the builder
        generates a fresh key per build, so an RSA-modulus anchor would catch
        one sample in three. Hence no modulus rule: with a per-build key there
        is nothing to pin.
      * lib/{arm64-v8a,armeabi-v7a}/libmetamask_loader.so - the same filename
        in all three.
      * the code package "com.example.MetaMask" while the manifest package is
        "com.p<8 hex>.tiktok18" - the package name is randomised, the code
        package left on the Android Studio default. The same mistake as
        "com.nameown12" in Venom. It CANNOT be used, though - see below.

    WHY THE WHOLE RULE LIVES IN THE RAW PASS - measured, and the most
    important thing here:
    these APKs have bit 0 of the ZIP general-purpose flags set, i.e. the "entry
    is encrypted" marker. Android ignores it and installs the app, but zipfile
    refuses (RuntimeError "File is encrypted"). The scope varies per sample:
      b00c61bf  classes.dex and AndroidManifest.xml marked,
      e56cd724  EVERY entry marked - the content-pass buffer comes out
                completely EMPTY.
    The consequence is that the "com.example.MetaMask.*" components, visible to
    androguard (which has a more forgiving reader), are unreachable for the
    scanner. Any rule resting on strings from the manifest or the DEX would be
    dead on this cluster. That leaves the certificate DER and the ZIP entry
    names - both of which live in the raw-file pass.
*/

rule MetaMask_Loader_Builder_Cert
{
    meta:
        description = "Dropper builder leaving unfilled tool defaults in the certificate subject (O=Org, L=City, ST=State) - TikTok18 lures and others"
        family = "MetaMask loader / RS builder"
        note = "the subject identifies the BUILDER, not the operator - the key is generated per build (8 different keys across 8 samples)"
        samples_seen = 8
        distinct_certs = 8
        vt_range = "10-19 / 76"
        first_seen = "2026-09"
    strings:
        // The anchors cover the attribute OID and the string header, not the
        // text alone, so they can only land inside a DER Name structure.
        // 06 03 55 04 0a = OID 2.5.4.10 (organizationName), 13 03 = PrintableString(3)
        $o = { 06 03 55 04 0a 13 03 4f 72 67 }
        // 06 03 55 04 07 = OID 2.5.4.7 (localityName), 13 04 = PrintableString(4)
        $l = { 06 03 55 04 07 13 04 43 69 74 79 }
        // 06 03 55 04 08 = OID 2.5.4.8 (stateOrProvinceName), 13 05 = PrintableString(5)
        $st = { 06 03 55 04 08 13 05 53 74 61 74 65 }
    condition:
        // There is deliberately NO CN here, and that is a correction after
        // measurement rather than a simplification. The first version demanded
        // CN=main_app and thereby missed 5 of the cluster's 8 samples: the
        // database holds THREE CN variants with an otherwise identical subject
        // - "main_app" (3 samples), "App" (4), "dog" (1). So CN is the varying
        // part and the constant is the full set of three unfilled tool
        // defaults. Measured on all eight samples: the $o, $l and $st bytes
        // are identical in every one.
        //
        // All three at once, because each alone is far too common; it is the
        // combination "Org" + "City" + "State" in fields a human would fill in
        // sensibly that is the signal. In the database 8 of 8 such samples sit
        // at VT 10-19; not one is clean.
        all of them
}

rule MetaMask_Loader_Payload
{
    meta:
        description = "The libmetamask_loader.so native library - payload of droppers impersonating the MetaMask wallet"
        family = "MetaMask loader"
        note = "kept separate from the certificate rule so a build signed with another key is still caught"
        samples_seen = 3
        first_seen = "2026-09"
    strings:
        $arm64 = "lib/arm64-v8a/libmetamask_loader.so" ascii
        $arm32 = "lib/armeabi-v7a/libmetamask_loader.so" ascii
    condition:
        // ZIP entry names from the raw-file pass. Each appears twice (local
        // header plus central directory), but "any" is enough: a genuine
        // MetaMask wallet does not name a library this way.
        any of them
}

rule APK_Entries_Flagged_As_Encrypted
{
    meta:
        description = "APK entries with the ZIP 'encrypted' bit set - Android ignores it and installs anyway, analysis tools refuse to unpack"
        technique = "ZIP encryption flag abuse"
        note = "found on the tiktok18/MetaMask cluster. Effect on this repo: yara_scanner skips such an entry, so rules resting on its strings quietly fail to fire (reported in _decompressed_content)"
        samples_seen = 3
        first_seen = "2026-09"
    strings:
        // Local file header: signature(4) version(2) FLAGS(2) method(2)
        // time(2) date(2) crc(4) csize(4) usize(4) namelen(2) extralen(2),
        // name from offset 30 - hence the [26] between signature and name.
        // We anchor on two entries that MUST exist in any APK.
        $lfh_manifest = { 50 4b 03 04 [26] 41 6e 64 72 6f 69 64 4d 61 6e 69 66 65 73 74 2e 78 6d 6c }
        $lfh_dex = { 50 4b 03 04 [26] 63 6c 61 73 73 65 73 2e 64 65 78 }
    condition:
        // Bit 0 of the general-purpose flags (offset +6 from the signature)
        // means "encrypted". A well-formed APK has no business setting it:
        // Android does not support ZIP encryption, so the only reason to set
        // it is to mislead tools that honour the bit.
        for any i in (1..#lfh_manifest) : ( uint16(@lfh_manifest[i] + 6) & 1 == 1 )
        or for any i in (1..#lfh_dex) : ( uint16(@lfh_dex[i] + 6) & 1 == 1 )
}
