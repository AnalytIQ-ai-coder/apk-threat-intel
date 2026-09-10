/*
    Banker/RAT podszywajacy sie pod brazylijskie marki, z rodzina komponentow
    nazwanych wedlug szablonu "proxy.adapter.op<Typ><slowo>".

    PODSTAWA DOWODOWA: JEDNA PROBKA. Tak samo malo jak przy venom_tools.yar
    i z tymi samymi konsekwencjami dla ostroznosci — przy n=1 nie da sie
    odroznic odcisku buildera od artefaktu pojedynczego builda.
      157d96e7  emulator.differentiator.pinger  "Bradesco Saude"  21/75  2026-09-10
      klucz testowy AOSP 61ED377E (publiczny, wiec bezuzyteczny jako kotwica)

    CO ZMIERZONO: 25 klas w classes.dex w pakiecie "proxy/adapter/", nazwanych
    wedlug jednego szablonu — przedrostek "op", typ komponentu androidowego
    i zwykle angielskie slowo:
      opActivity{cataloger,converter,coremesh,expander,parser,pulsehub,
                 scheduler,transmitter,watcher}
      opReceiver{archiver,authorizer,conductor,emulator,parser,recycler,
                 repeater,shuffler}
      opService{conductor,enforcer,manager,parser,poller,responder,scanner,
                watchdog}
    17 z nich jest zadeklarowanych w manifescie jako uslugi i odbiorcy.
    Obok nich stoja komponenty o nazwach czysto losowych (isastmopirhmuy,
    oiftagxtkpymrvc) — czyli randomizacja W TEJ SAMEJ PROBCE dziala tylko na
    czesc nazw, a szablon "proxy.adapter.op*" zostal nietkniety. To sugeruje,
    ze pochodzi z warstwy buildera, a nie z generatora nazw. Sugeruje — przy
    jednej probce nie jest to rozstrzygniete.

    CZEGO SWIADOMIE NIE UZYWAM JAKO KOTWICY:
      * klucza — to publiczny klucz testowy AOSP, wspoldzielony przez modderow
        i autorow malware (patrz threat_db._CERT_SUBJECT_NIEIDENTYFIKUJACE),
      * "jcraft.com" / "openssh.com" (biblioteka SSH JSch w srodku bankera,
        czyli tunel zwrotny) — zmierzone w bazie: te domeny wystepuja w OSMIU
        probkach, w tym w legalnych "Servers Ultimate", "SeekVPN", "FanVPN"
        i "AIO Streamer". Jako dyskryminator sa bezwartosciowe, mimo ze
        w kontekscie tej probki sa ciekawe,
      * etykiety "Bradesco Saude" — marka jest podszywana szeroko i przez
        niepowiazanych operatorow.

    PRZEBIEG SKANERA: deskryptory klas siedza w zdeflatowanym classes.dex,
    wiec regula dziala WYLACZNIE w przebiegu po odkompresowanej zawartosci.
    W przebiegu po surowym pliku tych ciagow nie ma — sprawdzone, takze
    w formie UTF-16 z manifestu.
*/

rule Proxy_Adapter_Komponenty
{
    meta:
        description = "Rodzina komponentow 'proxy.adapter.op<Typ><slowo>' — szablon nazw buildera bankera podszywajacego sie pod marki brazylijskie"
        family = "proxy.adapter"
        uwaga = "podstawa dowodowa: 1 probka. Drugie trafienie rozstrzygnie, czy to odcisk buildera, czy jednego builda."
        samples_seen = 1
        vt = "21 / 75"
        first_seen = "2026-09"
    strings:
        // Deskryptor typu DEX. Slowa koncowego NIE zaszywamy — jest ich 25
        // roznych i moga byc losowane z puli; stalym elementem jest szablon
        // "Lproxy/adapter/op" plus nazwa typu komponentu androidowego.
        $svc = /Lproxy\/adapter\/opService[a-z]{4,14};/ ascii
        $rcv = /Lproxy\/adapter\/opReceiver[a-z]{4,14};/ ascii
        $act = /Lproxy\/adapter\/opActivity[a-z]{4,14};/ ascii
    condition:
        // Wszystkie trzy typy naraz i lacznie kilkanascie klas. Pojedyncze
        // trafienie moglaby dac przypadkowa aplikacja z pakietem "proxy.adapter";
        // komplet trzech typow po kilka sztuk kazdy juz nie.
        all of them and (#svc + #rcv + #act) >= 12
}
