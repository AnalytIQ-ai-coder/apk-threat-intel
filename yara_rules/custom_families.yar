/*
    Hand-written rules for families we identified in earlier runs of this
    pipeline. Each one is narrow on purpose: they name a specific campaign
    rather than a generic behaviour.
*/

rule ZloySync_RU_Banker
{
    meta:
        description = "Russian banker carrying the zloy.sync marker - an SMS grabber aimed at RU banks"
        family = "zloy.sync"
        first_seen = "2026-06"
    strings:
        $provider = "zloy.sync.StubContentProvider"
        $wildberries = "com.wildberries.ru"
        $modulbank = "modulbank.ru"
    condition:
        $provider or (2 of ($wildberries, $modulbank))
}

rule FakeMetaMask_ErmacOcto
{
    meta:
        description = "Fake MetaMask content providers plus a Pushy channel - Ermac/Octo stealing crypto"
        family = "Ermac/Octo (fake MetaMask)"
        first_seen = "2026-07"
    strings:
        $metamask_pkg = "com.example.MetaMask" ascii
        $pushy_api = "api.pushy.me"
        $pushy_mqtt = "mqtt.pushy.io"
    condition:
        $metamask_pkg and (any of ($pushy_api, $pushy_mqtt))
}

rule KKAlive_ChineseKeepalive_Banker
{
    meta:
        description = "Chinese banker with a keep-alive framework (WeChat backtrace libs plus the kkalive daemon)"
        family = "kkalive keep-alive (PLN Mobile)"
        first_seen = "2026-06"
    strings:
        $daemon = "asd.kkalive.com.daemon"
        $keep_provider = "asd.kkalive.com.keep.provider"
        $wechat_lib1 = "libwechatbacktrace.so"
        $wechat_lib2 = "libtrace-canary.so"
    condition:
        (any of ($daemon, $keep_provider)) and (any of ($wechat_lib1, $wechat_lib2))
}

rule USDT_TRC20_Clipper_Overlay
{
    meta:
        description = "Fake USDT (TRC20) transfer confirmation screen embedded as Base64 HTML - a crypto clipper"
        family = "USDT clipper overlay"
        first_seen = "2026-06"
    strings:
        $usdt = "Tether(USDT) - TRC20"
        $usdt2 = "Tether (USDT)-TRC20"
        $transfer_class = "transfer-amount"
        $trust_target = "com.wallet.crypto.trustapp"
    condition:
        (any of ($usdt, $usdt2)) and $transfer_class and $trust_target
}

rule Alien_FreeFire_Bangladesh
{
    meta:
        description = "Alien banker impersonating Free Fire apps, operator based in Bangladesh"
        family = "Alien (BD Free Fire)"
        first_seen = "2026-06"
    strings:
        $dev1 = "Pro_Developer" ascii
        $bd_wa = /wa\.me\/\+880\d{10}/
        $firebase = ".firebaseio.com"
    condition:
        $dev1 and (any of ($bd_wa, $firebase))
}

rule RTO_Challan_GithubDeaddrop
{
    meta:
        description = "Indian RTO-Challan banker with its C2 dead drop hosted on GitHub"
        family = "RTO Challan (uasecurity.org)"
        first_seen = "2026-07"
    strings:
        $uasecurity = "uasecurity.org"
        $ghdrop = "backend-url-provider"
        $rto = "Challan" nocase
    condition:
        $uasecurity and ($ghdrop or $rto)
}
