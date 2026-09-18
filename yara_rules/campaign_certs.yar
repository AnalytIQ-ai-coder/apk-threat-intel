/*
    Rules anchored on a campaign's SIGNING KEY rather than on its contents.

    YARA cannot compute a certificate's SHA-1 fingerprint (that is a hash over
    a structure inside the APK), so we match a slice of the public key's RSA
    modulus instead. The modulus is unique to a key pair and appears verbatim
    in the certificate DER - both in the v1 signature (META-INF/*.RSA) and in
    the v2/v3 block.

    Why this beats matching on the subject name: the "Wikimedia Foundation"
    certificate below is FORGED. Searching for that text would also hit the
    real Wikipedia app. The key modulus has no such problem - the forgery uses
    a different key from the original.

    Generated from the certificate clusters in output/threat_intel.db.
*/

rule Cert_Editor_MultiBrand
{
    meta:
        description = "One operator: NextGen mParivahan (IN), C6BANK (BR), a trojanised Niagara Launcher, MovieBox, Dixmax"
        family = "editor (CN=editor)"
        cert_sha1 = "927CA44949D7788AA86F9D7F04D7FDACECD1DFB9"
        cert_subject = "Common Name: editor"
        key = "RSA-2048, signature scheme v1"
        samples_seen = 17
        distinct_packages = 12
    strings:
        // slice of the signing key RSA modulus (bytes 16-48)
        $modulus = { 7b e2 ee 10 9b 77 a2 ab ec 5d ad d1 d1 5f 86 a8 2d 51 df 2d f2 e2 23 f4 84 b3 e8 85 9a 68 09 98 }
    condition:
        $modulus
}

rule Cert_NP_CrossContinent_Banker
{
    meta:
        description = "A campaign across three continents: HDFC/INDUSIND/SBI/mParivahan (IN), Cartao Protegido (BR), N26 Pdf (EU), TikTok18+"
        family = "np (CN=np)"
        cert_sha1 = "26B02D233509F4AECF56980032343456CEAB722A"
        cert_subject = "Common Name: np, Organizational Unit: np, Organization: np, Locality: 南京, State/Province: "
        key = "RSA-2048, signature scheme v1"
        samples_seen = 14
        distinct_packages = 12
    strings:
        // slice of the signing key RSA modulus (bytes 16-48)
        $modulus = { 30 72 0a 6f b4 ca 55 86 18 79 bc 80 57 d7 9a b4 9a 21 b3 a1 c1 82 af 30 06 91 de 99 73 30 d4 0f }
    condition:
        $modulus
}

rule Cert_FakeWikimedia_N26_Chrome
{
    meta:
        description = "Certificate impersonating the Wikimedia Foundation. 6x Certificato/Certificat N26 (IT/FR) plus 2x fake Google Chrome"
        family = "fake Wikimedia Foundation"
        cert_sha1 = "69FC6D6D250A14BCEB3E82DC7B547855888DE57E"
        cert_subject = "Common Name: Wikimedia Foundation, Organizational Unit: Mobile, Organization: Wikimedia Fo"
        key = "RSA-2048, signature scheme v2"
        samples_seen = 8
        distinct_packages = 8
    strings:
        // slice of the signing key RSA modulus (bytes 16-48)
        $modulus = { e7 26 8f 57 45 7b 87 9f 4a d2 db 54 f5 68 d6 31 a7 55 3d 94 3b d5 46 a1 4d cc 2d 77 81 00 84 fc }
    condition:
        $modulus
}

rule Cert_FakeAndroidNfc_AdultLure
{
    meta:
        description = "CN impersonating a system component. Adult lures written in homoglyphs: Seks18+, TikTok, HubPopka, SexHub18+"
        family = "fake com_android_nfc"
        cert_sha1 = "2CDC0BE9A0B9EC3D4A0D3A958023A770BA5A0A6D"
        cert_subject = "Common Name: com_android_nfc, Organizational Unit: Android, Organization: Google Inc., Loc"
        key = "RSA-4096, signature scheme v1"
        samples_seen = 5
        distinct_packages = 5
    strings:
        // slice of the signing key RSA modulus (bytes 16-48)
        $modulus = { 69 a7 b7 cd 6c 07 7b 86 66 ce 38 47 a0 ba 0b 01 61 8a 20 02 3a 61 10 05 c9 bb f4 15 0a 04 ca c4 }
    condition:
        $modulus
}

rule Cert_Tornado_Wallpapers
{
    meta:
        description = "A cluster of wallpaper apps all signed with one key"
        family = "Tornado"
        cert_sha1 = "64D74F8C5AB93D0FE5216C67EB7F2C90C2C67C56"
        cert_subject = "Common Name: Tornado, Organizational Unit: Tornado, Organization: Tornado, Locality: Bucha"
        key = "RSA-2048, signature scheme v2"
        samples_seen = 4
        distinct_packages = 4
    strings:
        // slice of the signing key RSA modulus (bytes 16-48)
        $modulus = { b6 1e 02 59 a3 b7 fa 3a b5 5a e6 5a e6 7b 56 9e 9a 90 72 cb 8c 44 09 7e 33 94 e9 24 f6 57 15 99 }
    condition:
        $modulus
}
