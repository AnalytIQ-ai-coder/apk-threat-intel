/*
    Cluster signed with the key "CN=Venom Tools, OU=Software, O=Venom Software,
    L=New York City, ST=New York, C=US"
    (SHA-1 936E0ACB069D912BE4FF6D10B5E799460719EBB6, RSA-2048, v2 signature,
    valid 2024-08-22 -> 2052-01-08).

    EVIDENCE BASE: ONE SAMPLE. Fewer than earth_signer.yar had (four), and too
    few to tell a BUILDER fingerprint from an artefact of ONE BUILD. The whole
    structure below follows from that: the anchors are separated by how much
    they risk, instead of being fused into a single condition.

      2ab4d9d01e2fd395aba7df5f3aec59b4899b0fc5f3295b55cd0d6664b010b285
      com.sgakagak.agakagabs, label "Chrome", 26/75 on VT, 300 kB, 14 ZIP entries

    WHY THE CERTIFICATE SUBJECT IS USED HERE AND NOT IN bsqzx_rentaapps.yar:
    "Venom Software" is the trade name of a RAT vendor, and an L field filled
    in with "New York City" is there to look plausible, not something an
    operator writes for themselves. Together that makes a DEFAULT SUBJECT BAKED
    INTO THE BUILDER - the same situation as "APK Signer/Earth". The
    consequence: the subject alone is NOT attribution to an operator, because
    every customer of the same tool gets the same text. Hence:
      * the KEY MODULUS rule pins one specific key pair -> one operator,
      * the SUBJECT rule, excluding that modulus, catches ANOTHER customer of
        the same builder -> a hunting signal, not attribution.

    THE CODE FINGERPRINT (measured on this one sample):
      * the manifest declares the package "com.sgakagak.agakagabs", but ALL the
        classes sit in "com.nameown12". The mismatch matters: the package name
        was randomised and the code package was not, which makes "nameown12"
        most likely a fixed builder template. Most likely - at n=1 it is still
        a hypothesis.
      * classes named after Java KEYWORDS: Lfddo/break;, Lfddo/case;,
        Lfddo/catch;, Lfddo/const;, Lfddo/goto;, Lfddo/new;, Lfddo/super;,
        Lfddo/this;, Lfddo/try;. Legal in DEX, illegal in Java source - so a
        decompiler either emits code that will not compile or falls over. The
        "fddo" segment itself may be randomised per build, which is why the
        rule matches a PATTERN (any short package plus a keyword) rather than
        that literal text.
      * device-admin permissions in res/xml/: wipe-data, reset-password,
        force-lock, disable-camera, watch-login, expire-password - the full set
        including data wipe. NOT usable in a rule, because res/xml/*.xml
        reaches neither of the scanner's two passes (see below).
      * an accessibility-service with canPerformGestures - touch synthesis,
        i.e. the ability to tap on the user's behalf.

    SCANNER PASSES - why this is five rules rather than one:
    yara_scanner scans the raw file first, then SEPARATELY the concatenated
    decompressed entries (.dex, .arsc, .so, AndroidManifest.xml, assets/).
    A string from one pass cannot sit in a condition with a string from the
    other, because such a branch will never fire - that is what the first
    earth_signer.yar tripped over.
      * certificate DER (v2 signature block)   -> RAW pass,
      * class descriptors from classes.dex     -> CONTENT pass,
      * ZIP entry names (lib/.../libvixt.so)   -> RAW pass.
    The name "libvixt.so" is deliberately absent from every condition: with one
    sample there is no telling a fixed payload name from a per-build random
    one, and the rentaapps family in the same database randomises it every time
    (libluggage, libdove, libhorror, libsharp...). It stays here as an
    observation to check against a second sample.

    THE SWAPPED MANIFEST COMPRESSION METHOD - measured, not assumed:
    this sample's AndroidManifest.xml declares compression method 17180 in the
    central directory and 32040 in the local header. Both are invalid (ZIP
    knows 0, 8, 9, 12, 14) and, tellingly, DIFFERENT from each other. There are
    two practical consequences:
      * Python's zipfile raises NotImplementedError, so _decompressed_content
        in yara_scanner SKIPS that entry - every rule resting on manifest
        strings is BLIND on this sample and nobody would find out, because the
        exception is swallowed. That includes
        APK_Permissions_Named_With_Leading_Digit from earth_signer.yar.
      * androguard has a more forgiving decoder and reads the manifest without
        complaint, so static analysis sees all 30 permissions. The gap between
        what the parser sees and what the rule scanner sees is the entire point
        of the technique.
    That is why $pkg_axml matches in the RAW pass rather than the content one:
    the manifest stream contains long literal runs, so the UTF-16 text sits in
    the file as plain bytes. That is a property of this particular file, not a
    general rule - what carries the match independently of the manifest is
    $pkg_dex.
*/

rule Venom_Tools_Operator_Key
{
    meta:
        description = "APK signed with one specific Venom Software builder key - an SMS/accessibility trojan with full device admin, posing as Chrome"
        family = "Venom Software"
        cert_sha1 = "936E0ACB069D912BE4FF6D10B5E799460719EBB6"
        cert_subject = "CN=Venom Tools, OU=Software, O=Venom Software, L=New York City"
        key = "RSA-2048, signature scheme v2"
        samples_seen = 1
        vt = "26 / 75"
        first_seen = "2026-09"
    strings:
        // RSA modulus slice (bytes 16-48), same approach as campaign_certs.yar.
        // The modulus is unique to a key pair, so it pins the operator rather
        // than the product.
        $modulus = { c5 fd 29 98 06 ed 61 3b c4 cf 2e 4a f2 8b 7c ad ec 89 14 f9 68 48 e2 62 2e 8a 8f 1c ea 21 cd 1a }
    condition:
        $modulus
}

rule Venom_Tools_Builder_Other_Key
{
    meta:
        description = "The Venom Software certificate subject with a key OTHER than the known one - another customer of the same builder, needs confirmation"
        family = "Venom Software (hunting)"
        note = "the subject is a tool default, so every customer shares it - a lead about the builder, not attribution of the operator"
        first_seen = "2026-09"
    strings:
        // The anchors cover the attribute OID and the PrintableString header
        // rather than the text alone, so they land only inside a DER Name
        // structure and not on the words "Venom Tools" sitting anywhere else
        // in the file.
        // 06 03 55 04 03 = OID 2.5.4.3 (commonName), 13 0b = PrintableString(11)
        $dn_cn = { 06 03 55 04 03 13 0b 56 65 6e 6f 6d 20 54 6f 6f 6c 73 }
        // 06 03 55 04 0a = OID 2.5.4.10 (organizationName), 13 0e = PrintableString(14)
        $dn_o = { 06 03 55 04 0a 13 0e 56 65 6e 6f 6d 20 53 6f 66 74 77 61 72 65 }
        $modulus = { c5 fd 29 98 06 ed 61 3b c4 cf 2e 4a f2 8b 7c ad ec 89 14 f9 68 48 e2 62 2e 8a 8f 1c ea 21 cd 1a }
    condition:
        // Both attributes at once, so an unrelated organisation happening to be
        // called "Venom Software" is not enough. "not $modulus" is deliberate:
        // a sample with the known key should be caught by the rule above, and a
        // hit HERE should mean "same builder, new key - check by hand".
        $dn_cn and $dn_o and not $modulus
}

rule Venom_Tools_Code_Package_nameown12
{
    meta:
        description = "Classes in the com.nameown12 package while the manifest declares a different package - an unrenamed Venom Software builder template"
        family = "Venom Software"
        note = "a hypothesis from one sample: the manifest package name was randomised, the code package was not. A second hit will confirm or refute it."
        first_seen = "2026-09"
    strings:
        // Type descriptor from classes.dex.
        $pkg_dex = "com/nameown12/" ascii
        // The same name in the AndroidManifest.xml string pool - AXML stores
        // these in UTF-16, hence "wide". The manifest also goes through the
        // content pass.
        $pkg_axml = "com.nameown12" wide
    condition:
        any of them
}

rule Obfuscator_Classes_Named_After_Keywords
{
    meta:
        description = "DEX contains classes named after Java keywords (break, const, goto, catch...) - legal in bytecode, uncompilable in source, so it breaks decompilers"
        technique = "anti-decompilation / keyword class naming"
        note = "narrow evidence base - see the file header. The threshold of 6 distinct keywords is there to filter out a single chance hit in binary data."
        first_seen = "2026-09"
    strings:
        // DEX type descriptor: "L" + short package + "/" + keyword + ";".
        // The package is a pattern rather than fixed text, because the "fddo"
        // segment from the only known sample may be randomised per build.
        $kw_break = /L[a-z]{2,10}\/break;/ ascii
        $kw_case = /L[a-z]{2,10}\/case;/ ascii
        $kw_catch = /L[a-z]{2,10}\/catch;/ ascii
        $kw_class = /L[a-z]{2,10}\/class;/ ascii
        $kw_const = /L[a-z]{2,10}\/const;/ ascii
        $kw_else = /L[a-z]{2,10}\/else;/ ascii
        $kw_final = /L[a-z]{2,10}\/final;/ ascii
        $kw_goto = /L[a-z]{2,10}\/goto;/ ascii
        $kw_new = /L[a-z]{2,10}\/new;/ ascii
        $kw_super = /L[a-z]{2,10}\/super;/ ascii
        $kw_this = /L[a-z]{2,10}\/this;/ ascii
        $kw_try = /L[a-z]{2,10}\/try;/ ascii
    condition:
        // Works in the DECOMPRESSED-content pass - classes.dex is deflated, so
        // the raw-file pass does not contain these strings.
        6 of them
}

rule APK_Manifest_Swapped_Compression_Method
{
    meta:
        description = "AndroidManifest.xml declared with an invalid ZIP compression method - Android opens it, standard analysis tooling does not"
        technique = "ZIP compression method confusion"
        note = "found on the Venom sample (method 17180 in the central directory, 32040 in the local header). 1 positive sample, 6 negative."
        effect = "yara_scanner swallows the NotImplementedError and skips the manifest, so rules on manifest strings quietly fail to fire"
        first_seen = "2026-09"
    strings:
        // ZIP local file header, immediately followed by the file name:
        // signature(4) version(2) flags(2) method(2) time(2) date(2) crc(4)
        // csize(4) usize(4) namelen(2) extralen(2) = name at offset 30.
        // Hence the [26] between signature and name.
        $lfh_manifest = { 50 4b 03 04 [26] 41 6e 64 72 6f 69 64 4d 61 6e 69 66 65 73 74 2e 78 6d 6c }
    condition:
        // The specific value is deliberately NOT pinned - with one sample
        // there is no telling whether the builder randomises it. Instead we
        // read the method field directly (offset +8 from the signature) and
        // reject the only two that make sense in an APK: 0 (STORED) and
        // 8 (DEFLATE). Anything else is either evasion or a damaged file, and
        // both are worth a look.
        for any i in (1..#lfh_manifest) : (
            uint16(@lfh_manifest[i] + 8) != 0 and uint16(@lfh_manifest[i] + 8) != 8
        )
}
