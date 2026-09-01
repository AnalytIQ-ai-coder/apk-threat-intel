/*
    Reguly kotwiczone na KLUCZU PODPISUJACYM kampanii, nie na jej zawartosci.

    YARA nie policzy odcisku SHA-1 certyfikatu (to skrot ze struktury wewnatrz
    APK), wiec dopasowujemy fragment modulu RSA klucza publicznego. Modul jest
    unikalny dla pary kluczy i wystepuje doslownie w DER certyfikatu — zarowno
    w podpisie v1 (META-INF/*.RSA), jak i w bloku v2/v3.

    Zaleta nad dopasowaniem po nazwie podmiotu: certyfikat "Wikimedia
    Foundation" ponizej jest PODROBIONY. Gdybysmy szukali tego napisu,
    trafialibysmy tez w prawdziwa aplikacje Wikipedii. Modul klucza tego
    problemu nie ma — falszywka ma inny klucz niz oryginal.

    Wygenerowane z klastrow certyfikatow w output/threat_intel.db.
*/

rule Cert_Editor_MultiBrand
{
    meta:
        description = "Jeden operator: NextGen mParivahan (IN), C6BANK (BR), trojanizowany Niagara Launcher, MovieBox, Dixmax"
        family = "editor (CN=editor)"
        cert_sha1 = "927CA44949D7788AA86F9D7F04D7FDACECD1DFB9"
        cert_subject = "Common Name: editor"
        key = "RSA-2048, schemat podpisu v1"
        samples_seen = 17
        distinct_packages = 12
    strings:
        // fragment modulu RSA klucza podpisujacego (bajty 16-48)
        $modulus = { 7b e2 ee 10 9b 77 a2 ab ec 5d ad d1 d1 5f 86 a8 2d 51 df 2d f2 e2 23 f4 84 b3 e8 85 9a 68 09 98 }
    condition:
        $modulus
}

rule Cert_NP_CrossContinent_Banker
{
    meta:
        description = "Kampania na trzech kontynentach: HDFC/INDUSIND/SBI/mParivahan (IN), Cartao Protegido (BR), N26 Pdf (EU), TikTok18+"
        family = "np (CN=np)"
        cert_sha1 = "26B02D233509F4AECF56980032343456CEAB722A"
        cert_subject = "Common Name: np, Organizational Unit: np, Organization: np, Locality: 南京, State/Province: "
        key = "RSA-2048, schemat podpisu v1"
        samples_seen = 14
        distinct_packages = 12
    strings:
        // fragment modulu RSA klucza podpisujacego (bajty 16-48)
        $modulus = { 30 72 0a 6f b4 ca 55 86 18 79 bc 80 57 d7 9a b4 9a 21 b3 a1 c1 82 af 30 06 91 de 99 73 30 d4 0f }
    condition:
        $modulus
}

rule Cert_FakeWikimedia_N26_Chrome
{
    meta:
        description = "Certyfikat podszywa sie pod Wikimedia Foundation. 6x Certificato/Certificat N26 (IT/FR) + 2x fake Google Chrome"
        family = "fake Wikimedia Foundation"
        cert_sha1 = "69FC6D6D250A14BCEB3E82DC7B547855888DE57E"
        cert_subject = "Common Name: Wikimedia Foundation, Organizational Unit: Mobile, Organization: Wikimedia Fo"
        key = "RSA-2048, schemat podpisu v2"
        samples_seen = 8
        distinct_packages = 8
    strings:
        // fragment modulu RSA klucza podpisujacego (bajty 16-48)
        $modulus = { e7 26 8f 57 45 7b 87 9f 4a d2 db 54 f5 68 d6 31 a7 55 3d 94 3b d5 46 a1 4d cc 2d 77 81 00 84 fc }
    condition:
        $modulus
}

rule Cert_FakeAndroidNfc_AdultLure
{
    meta:
        description = "CN podszywa sie pod komponent systemowy. Przynety dla doroslych z homoglifami: Seks18+, TikTok, HubPopka, SexHub18+"
        family = "fake com_android_nfc"
        cert_sha1 = "2CDC0BE9A0B9EC3D4A0D3A958023A770BA5A0A6D"
        cert_subject = "Common Name: com_android_nfc, Organizational Unit: Android, Organization: Google Inc., Loc"
        key = "RSA-4096, schemat podpisu v1"
        samples_seen = 5
        distinct_packages = 5
    strings:
        // fragment modulu RSA klucza podpisujacego (bajty 16-48)
        $modulus = { 69 a7 b7 cd 6c 07 7b 86 66 ce 38 47 a0 ba 0b 01 61 8a 20 02 3a 61 10 05 c9 bb f4 15 0a 04 ca c4 }
    condition:
        $modulus
}

rule Cert_Tornado_Wallpapers
{
    meta:
        description = "Klaster aplikacji z tapetami podpisanych jednym kluczem"
        family = "Tornado"
        cert_sha1 = "64D74F8C5AB93D0FE5216C67EB7F2C90C2C67C56"
        cert_subject = "Common Name: Tornado, Organizational Unit: Tornado, Organization: Tornado, Locality: Bucha"
        key = "RSA-2048, schemat podpisu v2"
        samples_seen = 4
        distinct_packages = 4
    strings:
        // fragment modulu RSA klucza podpisujacego (bajty 16-48)
        $modulus = { b6 1e 02 59 a3 b7 fa 3a b5 5a e6 5a e6 7b 56 9e 9a 90 72 cb 8c 44 09 7e 33 94 e9 24 f6 57 15 99 }
    condition:
        $modulus
}
