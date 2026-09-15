"""One-off helper: pull campaign certificate DERs and derive YARA anchors.

Run by hand when a new campaign cert shows up and we want its RSA modulus
slice to pin a rule on. Writes cert_anchors.json next to the script.
"""
import hashlib
import io
import json
import sys

from androguard.core.apk import APK
from asn1crypto import x509

from cert_analyzer import extract_cert_der
from isolation import run_isolated
from mwdb_client import get_client

# SHA-1 of the certificate -> SHA-256 of a sample known to carry it.
TARGETS = {
    "927CA44949D7788AA86F9D7F04D7FDACECD1DFB9": "495a5ef312cfd6d178b8426e0b65d6dd8d75bb21ca8e587de3d4f8dc293a8216",
    "26B02D233509F4AECF56980032343456CEAB722A": "1ba4bb9f0990697fa0c3b12ddf2d1f31ef385e14556c081f3f5e30dcbbf50f1a",
    "69FC6D6D250A14BCEB3E82DC7B547855888DE57E": "db2c9949fae4e779f1d988d38b67ed9b3612dbf11c1159c791093aeef9cdab2c",
    "2CDC0BE9A0B9EC3D4A0D3A958023A770BA5A0A6D": "3a03b35a4c614d651954f8298d5bb75abe33223e0791bdc1b9bdb2af69d3009b",
    "64D74F8C5AB93D0FE5216C67EB7F2C90C2C67C56": "2ca53b67e4c7da644ecfe2c3b4ddf8542cc1b3dde6f9d7254220424226d1f918",
}

ANCHORS_FILE = "cert_anchors.json"


def _cert_der_from_bytes(apk_bytes):
    return extract_cert_der(APK(apk_bytes, raw=True))


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    mwdb = get_client()
    anchors = {}

    for sha1, sha256 in TARGETS.items():
        data = mwdb.query_file(sha256).download()
        # Parsing happens out of process: these are live malware samples.
        der, scheme = run_isolated(_cert_der_from_bytes, (data,), timeout=90)
        assert hashlib.sha1(der).hexdigest().upper() == sha1, "fingerprint mismatch"

        cert = x509.Certificate.load(der)
        modulus = cert.public_key["public_key"].parsed["modulus"].native
        modulus_bytes = modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")

        # Bytes 16..48 of the modulus: past the leading structure, long enough
        # that a collision is not a concern, short enough to read in a rule.
        anchors[sha1] = {
            "subject": cert["tbs_certificate"]["subject"].human_friendly,
            "signature_scheme": scheme,
            "modulus_bits": modulus.bit_length(),
            "anchor": modulus_bytes[16:48].hex(),
        }
        print("%s  %s  RSA-%d  %s..." % (
            sha1[:16], scheme, modulus.bit_length(), modulus_bytes[16:48].hex()[:24]))

    io.open(ANCHORS_FILE, "w", encoding="utf-8").write(
        json.dumps(anchors, indent=2, ensure_ascii=False))
    print("\nwrote %s" % ANCHORS_FILE)


if __name__ == "__main__":
    main()
