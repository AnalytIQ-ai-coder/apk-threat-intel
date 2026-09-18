/*
    The "rentaapps" / System_Upgrade campaign - a dropper with C2 at bsqzx.xyz.

    13 samples, 12 distinct package names (ghy.<three letters>.rentaapps), all
    with the app label "System_Upgrade", VT 8-18/75, tagged "dropper". Every
    sample carries EXACTLY ONE native library at entropy ~7.996 (encrypted, not
    merely packed) under a random name: libearth.so, libflag.so, libempty.so,
    libbench.so, libbot.so... Randomising that filename is a deliberate evasion,
    so the rule must NOT rest on it.

    WHY NOT THE SIGNING KEY (unlike campaign_certs.yar): the whole cluster is
    signed with the AOSP test key
    (SHA-1 27196E386B875E76ADF700E7EA84E4C6EEE33DFA). That key is PUBLIC - it
    sits in the Android source tree and everyone building with testkey uses it.
    In our own database four unrelated families carry the same key
    (com.liquidity.sweeps.core, DIXMAX TV, net.nccjus.kedkgbv, teuq.lbnn.zzo),
    so 5 of 18 samples are NOT this campaign. An RSA-modulus anchor here would
    misattribute and fire on any test build of Android.

    So we anchor on the C2 and on the builder fingerprint instead.
*/

rule Rentaapps_C2_bsqzx
{
    meta:
        description = "'System_Upgrade' dropper from the rentaapps family - C2 bsqzx.xyz, package ghy.<xxx>.rentaapps, one encrypted native library under a random name"
        family = "rentaapps / bsqzx.xyz"
        c2 = "bsqzx.xyz"
        samples_seen = 13
        distinct_packages = 12
        vt_range = "8-18 / 75"
        cert_note = "AOSP test key 27196E386B875E76 - SHARED, unusable as an anchor"
        first_seen = "2026-09"
    strings:
        $c2      = "bsqzx.xyz" ascii
        $pkg_dot = "rentaapps" ascii
        $prov    = "com.launcher.mango.LauncherProvider" ascii
        $prov_l  = "Lcom/launcher/mango/LauncherProvider" ascii
        $label   = "System_Upgrade" ascii
    condition:
        // The known C2 only. The domain appears nowhere outside this campaign,
        // so hitting it is sufficient grounds on its own.
        // The builder fingerprint without a C2 is handled by the SEPARATE rule
        // below - as an OR branch here it would never fire.
        $c2 and any of ($pkg_dot, $prov, $prov_l, $label)
}

rule Rentaapps_Builder_New_Domain
{
    meta:
        description = "The rentaapps builder fingerprint with no known C2 - likely a new wave on a rotated domain"
        family = "rentaapps (builder)"
        samples_seen = 13
        first_seen = "2026-09"
    strings:
        $pkg_dot = "rentaapps" ascii
        $label   = "System_Upgrade" ascii
        $prov    = "com.launcher.mango" ascii
        $prov_l  = "Lcom/launcher/mango" ascii
        $c2      = "bsqzx.xyz" ascii
    condition:
        // "not $c2" is deliberate: this rule should only catch what the first
        // one did not, so that a hit here means "new domain, go look at it".
        not $c2 and $pkg_dot and $label and any of ($prov, $prov_l)
}
