/*
    Reguły napisane na podstawie próbek faktycznie widzianych w tym pipeline'ie
    (nie ogólne sygnatury branżowe). Każda odpowiada rodzinie/kampanii, którą
    zidentyfikowaliśmy ręcznie w raportach threat-intel.
*/

rule ZloySync_RU_Banker
{
    meta:
        description = "Rosyjski banker z markerem zloy.sync — SMS-grabber celujący w ru-banki"
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
        description = "Fałszywe content-providery MetaMask + kanał Pushy — Ermac/Octo kradnące krypto"
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
        description = "Chiński banker z frameworkiem keep-alive (WeChat backtrace libs + kkalive daemon)"
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
        description = "Fałszywy ekran potwierdzenia przelewu USDT (TRC20) osadzony jako Base64 HTML — crypto-clipper"
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
        description = "Banker Alien podszywający się pod aplikacje Free Fire, operator z Bangladeszu"
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
        description = "Indyjski banker RTO-Challan z dead-dropem C2 hostowanym na GitHub"
        family = "RTO Challan (uasecurity.org)"
        first_seen = "2026-07"
    strings:
        $uasecurity = "uasecurity.org"
        $ghdrop = "backend-url-provider"
        $rto = "Challan" nocase
    condition:
        $uasecurity and ($ghdrop or $rto)
}
