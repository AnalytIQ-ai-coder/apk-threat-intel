/*
    Banker/RAT impersonating Brazilian brands, with a family of components
    named after the template "proxy.adapter.op<Type><word>".

    EVIDENCE BASE: ONE SAMPLE. As thin as venom_tools.yar was, and with the
    same consequences for caution - at n=1 you cannot tell a builder
    fingerprint from an artefact of one particular build.
      157d96e7  emulator.differentiator.pinger  "Bradesco Saude"  21/75  2026-09-10
      AOSP test key 61ED377E (public, therefore useless as an anchor)

    WHAT WAS MEASURED: 25 classes in classes.dex under the "proxy/adapter/"
    package, all named to one template - the prefix "op", an Android component
    type and an ordinary English word:
      opActivity{cataloger,converter,coremesh,expander,parser,pulsehub,
                 scheduler,transmitter,watcher}
      opReceiver{archiver,authorizer,conductor,emulator,parser,recycler,
                 repeater,shuffler}
      opService{conductor,enforcer,manager,parser,poller,responder,scanner,
                watchdog}
    17 of them are declared in the manifest as services and receivers.
    Alongside sit components with purely random names (isastmopirhmuy,
    oiftagxtkpymrvc) - so randomisation WITHIN THE SAME SAMPLE only touches
    some of the names and left the "proxy.adapter.op*" template alone. That
    suggests it comes from the builder layer rather than the name generator.
    Suggests - with one sample it is not settled.

    WHAT IS DELIBERATELY NOT USED AS AN ANCHOR:
      * the key - it is the public AOSP test key, shared by modders and malware
        authors alike (see threat_db._NON_IDENTIFYING_CERT_SUBJECTS),
      * "jcraft.com" / "openssh.com" (the JSch SSH library inside a banker,
        i.e. a reverse tunnel) - measured in the database: those domains appear
        in EIGHT samples, among them the legitimate "Servers Ultimate",
        "SeekVPN", "FanVPN" and "AIO Streamer". As a discriminator they are
        worthless, however interesting they are in this sample's context,
      * the "Bradesco Saude" label - the brand is impersonated widely and by
        unrelated operators.

    SCANNER PASS: class descriptors live inside the deflated classes.dex, so
    this rule only works in the decompressed-content pass. The raw-file pass
    does not contain these strings - checked, including in the UTF-16 form
    from the manifest.
*/

rule Proxy_Adapter_Components
{
    meta:
        description = "Component family 'proxy.adapter.op<Type><word>' - builder naming template of a banker impersonating Brazilian brands"
        family = "proxy.adapter"
        note = "evidence base: 1 sample. A second hit will settle whether this fingerprints the builder or one build."
        samples_seen = 1
        vt = "21 / 75"
        first_seen = "2026-09"
    strings:
        // DEX type descriptor. The trailing word is NOT pinned - there are 25
        // distinct ones and they may be drawn from a pool; what stays fixed is
        // the "Lproxy/adapter/op" template plus an Android component type.
        $svc = /Lproxy\/adapter\/opService[a-z]{4,14};/ ascii
        $rcv = /Lproxy\/adapter\/opReceiver[a-z]{4,14};/ ascii
        $act = /Lproxy\/adapter\/opActivity[a-z]{4,14};/ ascii
    condition:
        // All three types at once, and a dozen-plus classes in total. A single
        // hit could come from some unrelated app with a "proxy.adapter"
        // package; a full set of three types with several each could not.
        all of them and (#svc + #rcv + #act) >= 12
}
