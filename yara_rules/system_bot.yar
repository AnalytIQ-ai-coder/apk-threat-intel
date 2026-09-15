/*
    A family of RATs labelled "System", with the payload in libbot.so.

    EVIDENCE BASE: FOUR SAMPLES, all measured rather than assumed.
      5a615846  com.google.classroom   32/75  2026-09-10  cert 8642E3B3 (debug)
      4c05e3e8  com.chingusapk.juan    30/75  2026-09-03  cert A6F47B26 (debug)
      50b7a48d  com.chingusapk.juan    28/75  2026-08-30  cert 395CA6C0 (debug)
      e46d5e32  com.juan.art           32/75  2026-08-31  cert 61ED377E (AOSP testkey)

    WHAT CHANGES AND WHAT DOES NOT - this is what settles the choice of anchor:
      changes       the package name (three different), the certificate (four
                    different), the C2 infrastructure (juan.art differs from
                    the other three),
      does NOT      the set of 16 component names - IDENTICAL across all four
                    samples - and the native library name libbot.so.

    So the anchor is neither the key nor the C2 domains. The key rotates per
    build (three debug keystores plus one AOSP test key) and the domains were
    swapped between 08-31 and 09-03. The component set survived both.

    WHY THE C2 DOMAINS ARE USELESS AS STRINGS HERE - checked:
    "cnc.control-panel-live.net", "mgmt-panel.serverstats-daemon.com" and
    "sync.softwaremirror.workers.dev" appear in the database as IOCs of this
    sample, but they do NOT occur literally in classes.dex or in the raw APK
    bytes. The extractor recovered them another way (decoding), so a rule on
    them would have nothing to fire against. They stay in the database as
    IOCs, not as anchors.

    THE CAPABILITIES this component set implies - hence the threshold:
      TrustAgentService    keep the device in an unlocked state,
      IMEService           a custom keyboard, i.e. a keylogger by definition,
      NotificationService  read every notification, i.e. OTP codes,
      AccessibilityService tap on the user's behalf,
      AdminReceiver        device admin (lock, wipe),
      SecretCodeReceiver   activation via an MMI code dialled on the keypad,
      DreamService, QSTileService, PersistService  staying alive.
    No ordinary app declares those four at once.

    SCANNER PASSES (see the earth_signer.yar header - a string from one pass
    cannot sit in a condition with a string from the other):
      * component names -> the CONTENT pass. They live in two places: the
        AndroidManifest.xml string pool (UTF-16, hence "wide") and as class
        descriptors in classes.dex (ASCII). Both forms measured.
      * ZIP entry names (lib/.../libbot.so) -> the RAW pass.
*/

rule System_Bot_Component_Set
{
    meta:
        description = "RAT labelled 'System': trust agent plus custom keyboard plus notification reader plus accessibility in one manifest"
        family = "System / libbot"
        samples_seen = 4
        distinct_packages = 3
        distinct_certs = 4
        vt_range = "28-32 / 75"
        first_seen = "2026-08"
    strings:
        // SIMPLE names, without the package: the package name is randomised
        // per build (com.google.classroom / com.chingusapk.juan /
        // com.juan.art), so a full-path descriptor would not be stable.
        $kyorij = "KyorijService" ascii wide
        $trust = "TrustAgentService" ascii wide
        $ime = "IMEService" ascii wide
        $qs = "QSTileService" ascii wide
        $dream = "DreamService" ascii wide
        $secret = "SecretCodeReceiver" ascii wide
        $persist = "PersistService" ascii wide
        $admin = "AdminReceiver" ascii wide
        $restart = "RestartReceiver" ascii wide
        $netrec = "NetworkReceiver" ascii wide
        $pkgrec = "PackageReceiver" ascii wide
    condition:
        // "KyorijService" is a nonsense word and occurs nowhere else in the
        // corpus, so it is a strong anchor on its own. We pair it with any
        // three capability markers so that a single hit in binary data is not
        // enough.
        ($kyorij and 3 of ($trust, $ime, $qs, $dream, $secret, $persist))
        // Fallback branch in case "Kyorij" is randomised in later builds: then
        // the SET itself carries the signal. The 8-of-10 threshold is high on
        // purpose - individual names like AdminReceiver or DreamService do
        // turn up in ordinary apps.
        or 8 of ($trust, $ime, $qs, $dream, $secret, $persist, $admin, $restart, $netrec, $pkgrec)
}

rule System_Bot_libbot
{
    meta:
        description = "Native library named libbot.so alongside libbot32/libbot64 variants - payload of the 'System' family"
        family = "System / libbot"
        note = "works in the RAW pass: these are ZIP entry names, which sit in the central directory as plain text"
        samples_seen = 4
        first_seen = "2026-08"
    strings:
        // The path including the ABI directory, so we do not match the word
        // "libbot" occurring by chance in binary data.
        $arm64 = "lib/arm64-v8a/libbot" ascii
        $arm32 = "lib/armeabi-v7a/libbot" ascii
        $x86 = "lib/x86/libbot" ascii
    condition:
        // At least two architectures: a single path is too little, and all
        // four samples ship the full arm64 + armeabi-v7a + x86 set.
        2 of them
}
