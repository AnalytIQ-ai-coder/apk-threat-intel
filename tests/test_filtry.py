"""Testy regresyjne filtrow odsiewajacych falszywe IOC.

Uruchomienie: python tests/test_filtry.py   (nie wymaga pytest)

Kazdy przypadek pochodzi z faktycznego przebiegu analyzer.py, nie z wyobrazni.
W komentarzach jest zrodlo, zeby przy nastepnej zmianie regexa bylo widac,
czego dokladnie pilnuje dany assert.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dex_analyzer import (  # noqa: E402
    _DOMAIN_RE,
    _domena_jest_iocem,
    _find_targeted_packages,
    _is_plausible_ip,
)
from ioc_extractor import _BITBUCKET_RAW_RE, _WORKERS_DEV_RE  # noqa: E402

OVERLAY = ["android.permission.SYSTEM_ALERT_WINDOW"]
SMS = ["android.permission.RECEIVE_SMS"]


# ── Domeny: identyfikatory z kodu nie sa hostami ──────────────────────────────

def test_swizzle_glsl_odsiany():
    # Shadery w libflutter.so: dostep do skladowych wektora, a ".xyz" jest TLD.
    # Probka org.traccar.client wygenerowala a.xyz ... f.xyz plus K.xyz.
    for d in ("a.xyz", "b.xyz", "f.xyz", "K.xyz"):
        assert not _domena_jest_iocem(d), d


def test_jednoznakowe_domeny_zachowane():
    # Kontrprzyklad do powyzszego. Te sa prawdziwe i wystepuja w bazie
    # (g.co 16x, x.com 6x, a.applovin.com 9x) — regula na swizzle nie moze
    # ich zabrac, dlatego jest zawezona do TLD ".xyz".
    for d in ("g.co", "x.com", "a.applovin.com", "z.moatads.com"):
        assert _domena_jest_iocem(d), d


def test_dlugie_nazwy_klas_odsiane():
    # Nazwy klas Glide i shaderow Fluttera z string poola, zakonczone czyms
    # co wyglada na TLD. Prog dlugosci celowo wysoki — patrz test ponizej.
    for d in ("GifBitmapWrapperDrawableTranscoder.com",
              "FileDescriptorBitmapDecoder.com", "StreamBitmapDecoder.com",
              "AdvertisingIdClient.Info", "lightDirAndSpotCutoff.xyz",
              "genretrucklooksValueFrame.net"):
        assert not _domena_jest_iocem(d), d


def test_krotkie_camelcase_zachowane():
    # Kontrprzyklad, ktory obalil pierwsza wersje reguly: te hosty istnieja
    # naprawde i sa wartosciowym IOC dystrybucji pirackich APK. Odrzucanie
    # kazdego camelCase kosztowalo je wszystkie, wiec regula dziala dopiero
    # powyzej 18 znakow. Cena: CenterCrop.com zostaje falszywka.
    for d in ("HappyMod.com", "LEEAPK.COM", "JesusFreke.com", "YTPL.net",
              "9Mod.Com", "HE.net", "CaptchaKey.com"):
        assert _domena_jest_iocem(d), d


def test_ogony_pakietow_odsiane():
    # Odwrocony DNS: TLD na poczatku zamiast na koncu.
    for d in ("org.openjsse.net", "com.chrome.dev", "io.ktor.utils.io",
              "ru.vk.store.lib.network.info", "xyz.quaver.io"):
        assert not _domena_jest_iocem(d), d


def test_subdomeny_o_nazwie_tld_zachowane():
    # Drugi kontrprzyklad: "dev", "info" i "co" to popularne nazwy subdomen,
    # wiec nie moga wpasc pod regule odwroconego DNS mimo ze sa TLD.
    for d in ("dev.tapjoy.com", "dev.leanplum.com", "info.startappservice.com",
              "info.3g.qq.com"):
        assert _domena_jest_iocem(d), d


def test_placeholdery_odsiane():
    for d in ("www.example.com", "example.org", "domain.com", "test.com"):
        assert not _domena_jest_iocem(d), d


def test_placeholder_nie_lapie_po_podciagu():
    # "park-your-domain.com" zawiera "domain.com", ale to prawdziwy dostawca
    # dyn-DNS z probki com.icecoldapps.serversultimate. Dopasowanie musi byc
    # dokladne, inaczej gubimy realny host.
    assert _domena_jest_iocem("dynamicdns.park-your-domain.com")


def test_prawdziwe_domeny_przechodza():
    for d in ("panel.mp3pn.info", "evil-c2.top", "mp3pn.info",
              "captrustdb-default-rtdb.firebaseio.com", "deephost.in"):
        assert _domena_jest_iocem(d), d


def test_tld_kolidujace_z_kodem_odsiane():
    # ".top" i ".info" koliduja z geometria/CSS i z logowaniem czesciej niz
    # jakikolwiek inny TLD. W bazie na 36 domen ".top" prawdziwe byly cztery.
    for d in ("Rect.top", "LocalRect.top", "SystemUiOverlay.top", "window.top",
              "a.style.top", "a.top", "a.j.top", "console.info", "Log.INFO",
              "Log.private.info", "s.INFO", "Sharp.Info", "EVENTS.INFO",
              "feature.screen.info",
              # ".xyz" — swizzle i nazwy wektorow z shaderow
              "fragColor.xyz", "nCol.xyz", "vHsl.xyz", "extrudeRes.xyz",
              "color.xyz", "position.xyz", "texel.xyz", "materialParams.e.xyz",
              # ".io" — dispatchery i ogony pakietow Javy
              "Dispatchers.IO", "ExecutorProvider.IO", "Schedulers.io",
              "Socket.IO", "Ljava.io", "Start.io",
              # ".tk"
              "T.Tk"):
        assert not _domena_jest_iocem(d), d


def test_krotka_subdomena_cdn_zachowana():
    # Kontrprzyklad, ktory przesadzil o ksztalcie reguly. Kusilo, zeby odrzucac
    # jednoznakowa pierwsza etykiete ("x.print.processor.info"), ale pomiar na
    # bazie pokazal koszt: to prawdziwe hosty sieci reklamowej Ogury.
    # Trzeci raz w tym module ta sama pomylka — po g.co i a.applovin.com.
    for d in ("s.presage.io", "s.cloud.ogury.io", "s.qa.cloud.ogury.io"):
        assert _domena_jest_iocem(d), d


def test_prawdziwe_domeny_na_top_i_info_zachowane():
    # Kontrprzyklad: te TLD sa tanie i wlasnie dlatego popularne wsrod C2.
    # bsqzx.xyz i poker-rooms.top pochodza z probek wykrytych przez VT,
    # wiec regula nie moze wycinac tych koncowek hurtem.
    for d in ("poker-rooms.top", "cln9vhvfo2.top", "api.zold.top",
              "play.xpass.top", "api.waqi.info", "pirate-bay.info",
              "receive-sms-online.info", "mp3pn.info",
              # .xyz/.io/.tk sa tanie i wlasnie dlatego popularne wsrod C2
              "bsqzx.xyz", "pdlinkfortysix.xyz", "trkpp.xyz", "vidsrc.xyz",
              "api16-access-sg.pangle.io", "rx2.io", "ktor.io", "msg.io",
              "darkplaykids.tk", "www.darkplayapp.tk"):
        assert _domena_jest_iocem(d), d


def test_krotka_ale_prawdziwa_domena_zachowana():
    # Trzeci kontrprzyklad, ktory zmienil regule: odrzucanie kazdej etykiety
    # o dlugosci <= 2 zabieralo www.6b.top. Czysto literowe "a"/"s"/"j" to
    # nazwy zmiennych po minifikacji, ale "6b" to prawdziwa krotka domena.
    for d in ("www.6b.top", "tws.6b.top"):
        assert _domena_jest_iocem(d), d


# ── Dead-dropy ───────────────────────────────────────────────────────────────

def test_cloudflare_workers_to_deaddrop():
    # Ta sama klasa darmowej infrastruktury co .pages.dev. W bazie bylo
    # 9 takich hostow i zaden nie byl klasyfikowany jako dead-drop —
    # w tym sync.softwaremirror.workers.dev z probki wykrytej przez 30/75.
    for d in ("sync.softwaremirror.workers.dev",
              "damp-mouse-4d5a.smashystream.workers.dev",
              "m3u8.justchill.workers.dev",
              "multiplecdnqualities.apps-anime.workers.dev"):
        assert _WORKERS_DEV_RE.findall(d) == [d], d


def test_goly_workers_dev_to_nie_deaddrop():
    # Sama domena platformy nie jest IOC — dopiero konkretne konto.
    assert _WORKERS_DEV_RE.findall("workers.dev") == []


# ── Cele ataku: slowa-klucze dopasowane do segmentow, nie do podciagow ────────

def test_kawa_module_nie_jest_celem():
    # com.captchakey.superhigh (Kodular/App Inventor): slowo-klucz "modul"
    # od Modulbanku trafialo w angielskie "module" z runtime'u Kawa.
    wynik = _find_targeted_packages(
        ["kawa.standard.module_compile_options", "kawa.standard.module_name",
         "kawa.standard.module_static"], permissions=OVERLAY)
    assert wynik == [], wynik


def test_domena_nie_jest_pakietem():
    # _PKG_RE lapie "www.paypal.com" tak samo jak nazwe pakietu.
    wynik = _find_targeted_packages(["www.paypal.com"], permissions=OVERLAY)
    assert wynik == [], wynik


def test_biblioteki_kryptograficzne_nie_sa_celem():
    # Slowo-klucz "crypto" trafialo w javax.crypto i BouncyCastle, czyli
    # w kazda aplikacje uzywajaca szyfrowania.
    wynik = _find_targeted_packages(
        ["javax.crypto.spec", "org.bouncycastle.crypto.engines",
         "org.bouncycastle.crypto.params"], permissions=OVERLAY)
    assert wynik == [], wynik


def test_prawdziwe_cele_nadal_wykrywane():
    # Kontrprzyklad: poprawka nie moze zabic wykrywania faktycznych celow.
    wynik = _find_targeted_packages(
        ["com.idamob.tinkoff.android", "com.paypal.android.p2pmobile",
         "com.wallet.crypto.trustapp", "com.bankofamerica.mobile"],
        permissions=SMS)
    assert wynik == ["com.bankofamerica.mobile", "com.idamob.tinkoff.android",
                     "com.paypal.android.p2pmobile",
                     "com.wallet.crypto.trustapp"], wynik


def test_brak_uprawnien_to_brak_celow():
    # Launcher Niagara dostawal liste 31 "celow" bez zdolnosci ich atakowania.
    wynik = _find_targeted_packages(["com.bankofamerica.mobile"], permissions=[])
    assert wynik == [], wynik


# ── IP ────────────────────────────────────────────────────────────────────────

def test_ip_dokumentacyjne_odsiane():
    # 123.45.67.89 z com.icecoldapps.serversultimate to wzorzec w UI apki.
    for ip in ("123.45.67.89", "192.0.2.15", "198.51.100.7", "203.0.113.200"):
        assert not _is_plausible_ip(ip), ip


def test_numery_wersji_nie_sa_adresami():
    # Jedna probka (ibisPaint X) dala dziesiec takich naraz. W calej bazie
    # 26 ze 127 adresow ma wszystkie oktety <= 30 i kazdy jest numerem wersji.
    for ip in ("6.4.2.1", "8.3.6.1", "9.7.0.3", "13.6.2.0", "22.7.0.1",
               "23.3.0.1", "9.14.12.0", "6.17.0.1", "30.0.0.20"):
        assert not _is_plausible_ip(ip), ip


def test_resolwery_o_jednakowych_oktetach_zachowane():
    # Kontrprzyklad: 8.8.8.8 ma wszystkie oktety <= 30, ale to adres, nie wersja.
    # Numer wersji nigdy nie ma czterech jednakowych czlonow.
    #
    # Bez 1.1.1.1 celowo: ten adres odrzuca WCZESNIEJSZA regula, bo "1" jest
    # poczatkiem lukow OID w X.509 (2.5.4.3 = commonName itd.). To zachowanie
    # sprzed tej zmiany i osobny kompromis — resolwer Cloudflare jest cena za
    # odsianie fragmentow OID-ow, ktorych bylo w bazie duzo wiecej.
    for ip in ("8.8.8.8", "9.9.9.9"):
        assert _is_plausible_ip(ip), ip


def test_adres_z_portem_nie_jest_wersja():
    # Port oznacza kontekst sieciowy — takiego zapisu nie generuje numer wersji.
    assert _is_plausible_ip("30.10.216.161:12580")
    assert _is_plausible_ip("8.210.95.146:8089")


def test_prawdziwe_ip_przechodzi():
    for ip in ("8.8.8.8", "45.132.11.7", "185.220.101.44"):
        assert _is_plausible_ip(ip), ip


# ── Domeny: dopasowanie w srodku dluzszego identyfikatora ────────────────────
# Kazdy kontekst nizej jest DOSLOWNYM stringiem z DEX-a pobranej probki,
# nie rekonstrukcja. Zrodla: 61109fcc (com.appsgenz.launcherios.pro),
# 77c444c4 (com.cloudflare.onedotonedotonedotone), 2072c29a (Rasmlar5.apk).

def _werdykt(kontekst, oczekiwana):
    """Puszcza kontekst przez ten sam regex co pipeline i ocenia wskazane trafienie."""
    for m in _DOMAIN_RE.finditer(kontekst):
        if m.group() == oczekiwana:
            return _domena_jest_iocem(m.group(), kontekst, m.start(), m.end())
    raise AssertionError(f"regex nie znalazl {oczekiwana!r} w {kontekst!r}")


def test_glowa_dluzszego_identyfikatora_odsiana():
    # "camerax.core.io" to nazwa watku CameraX, "br.com" poczatek odwroconego
    # DNS-u, "rx2.io" wlasciwosc systemowa RxJavy. W bazie kolejno 13, 15 i 37
    # probek — najliczniejsza klasa falszywek, jakiej nie da sie rozpoznac
    # po samej wartosci dopasowania.
    assert not _werdykt("camerax.core.io.ioExecutor", "camerax.core.io")
    assert not _werdykt("pl.eobuwie.eobuwieapp,br.com.eventim.mobile.app.Android", "br.com")
    assert not _werdykt("rx2.io-priority", "rx2.io")
    assert not _werdykt("rx2.io-keep-alive-time", "rx2.io")


def test_ogon_dluzszego_identyfikatora_odsiany():
    # Flagi Firebase/Measurement. Regex nie siega w lewo, bo etykieta przed
    # kropka ma podkreslnik, wiec zostaje sam ogon wygladajacy jak host.
    assert not _werdykt(
        "measurement.collection.enable_session_stitching_token.client.dev", "client.dev")
    assert not _werdykt(
        "measurement.set_default_event_parameters_propagate_clear.service.dev", "service.dev")
    # Sklejka z puli stringow: "warp-edge/src/h3_tun.rs" + "cdnjs.cloudflare.com"
    # daja nieistniejacy host "rscdnjs.cloudflare.com".
    assert not _werdykt(
        "{{closure}}warp-edge/src/h3_tun.rscdnjs.cloudflare.com", "rscdnjs.cloudflare.com")


def test_host_z_obcietym_przedrostkiem_zachowany():
    # KONTRPRZYKLAD do testu wyzej i najwazniejszy assert w tym pliku.
    # Pierwsza wersja reguly odrzucala wszystko, przed czym stala kropka —
    # i zabierala cztery prawdziwe hosty Cloudflare z jednej probki.
    # Rozstrzyga znak PRZED kropka: identyfikator znaczy "smiec",
    # interpunkcja znaczy "prawdziwy host z wycietym przedrostkiem".
    assert _werdykt("*.cloudflareclient.com", "cloudflareclient.com")
    assert _werdykt("resolves DNS via DoH to `<gateway_unique_id>.cloudflare-gateway.com`",
                    "cloudflare-gateway.com")
    assert _werdykt(".is-cf.cloudflareresolve.com/resolvertest", "is-cf.cloudflareresolve.com")


def test_host_w_sciezce_z_myslnikiem_zachowany():
    # KONTRPRZYKLAD do reguly na myslnik. "index.crates.io" to prawdziwy host
    # rejestru Cargo, tyle ze wystepuje w nazwie katalogu z sufiksem-hashem.
    # Dlatego myslnikowa galaz wymaga czlonu czysto literowego ("-priority"),
    # a nie dowolnego ("-6f17d22bba15001f").
    assert _werdykt("/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/chrono-0.4.22",
                    "index.crates.io")


def test_host_w_url_zachowany():
    # Ukosnik przed hostem i za nim nie jest znakiem identyfikatora.
    assert _werdykt("https://liteapks.com/app.html", "liteapks.com")
    assert _werdykt("http://g.co/dev/packagevisibility.", "g.co")


def test_wersja_udajaca_domene_odsiana():
    # Wersje pythonowe z pakietow: 1.3.17.dev, 2.6.8.dev — 5 wierszy w bazie.
    for d in ("1.2.5.dev", "1.3.13.dev", "1.3.17.dev", "2.3.17.dev", "2.6.8.dev"):
        assert not _domena_jest_iocem(d), d


def test_domeny_z_samych_cyfr_zachowane():
    # KONTRPRZYKLAD: wymog DWOCH etykiet numerycznych nie jest ozdobnikiem.
    # 10010 to China Unicom, 10086 to China Mobile — prawdziwe domeny.
    assert _domena_jest_iocem("10010.com")
    assert _domena_jest_iocem("10086.cn")


def test_brak_kontekstu_nie_zmienia_werdyktu():
    # clean_iocs.py wola te funkcje na wartosciach z bazy, gdzie kontekstu juz
    # nie ma. Bez kontekstu test na fragment identyfikatora ma byc pomijany,
    # a nie zgadywany.
    assert _domena_jest_iocem("bsqzx.xyz")
    assert _domena_jest_iocem("banxicoprotec.org")
    assert _domena_jest_iocem("camerax.core.io")  # bez kontekstu nie da sie orzec


# ── Dead-dropy: Bitbucket ────────────────────────────────────────────────────

def test_bitbucket_raw_jest_dead_dropem():
    # Probki com.co.xb (NewPay) i com.safe.xp (XPay) trzymaja na Bitbuckecie
    # liste aktualnych domen C2. Wczesniej ladowalo to w bazie jako zwykly URL.
    for u in ("https://bitbucket.org/xpay2050/xinbipay/raw/main/domain.json",
              "https://bitbucket.org/xpay2050/xinbipay/raw/main/domain.json2"):
        assert _BITBUCKET_RAW_RE.findall(u), u


def test_bitbucket_api_src_jest_dead_dropem():
    # Odpowiednik raw.githubusercontent.com po stronie Bitbucketa.
    assert _BITBUCKET_RAW_RE.findall(
        "https://api.bitbucket.org/2.0/repositories/acme/cfg/src/main/c2.json")


def test_linki_do_zrodel_na_bitbuckecie_pomijane():
    # KONTRPRZYKLAD, ktory wymusza wymog "/raw/" w regule — dokladnie tak samo,
    # jak wykluczenie "/blob/" przy GitHubie. Te dwa adresy sa w bazie i
    # pochodza z komunikatow bibliotek o toolchainie LLVM, nie z malware.
    for u in ("https://bitbucket.org/loganchien/clang",
              "https://bitbucket.org/loganchien/llvm",
              "bitbucket.org"):
        assert not _BITBUCKET_RAW_RE.findall(u), u


if __name__ == "__main__":
    testy = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    bledy = 0
    for nazwa, fn in testy:
        try:
            fn()
            print(f"  OK    {nazwa}")
        except AssertionError as e:
            bledy += 1
            print(f"  BLAD  {nazwa}: {e}")
    print(f"\n{len(testy) - bledy}/{len(testy)} przeszlo")
    sys.exit(1 if bledy else 0)
