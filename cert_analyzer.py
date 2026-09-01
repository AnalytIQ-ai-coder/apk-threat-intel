import datetime
import hashlib

from loguru import logger
# Ten modul bywa importowany samodzielnie (np. przez skrypty narzedziowe),
# ktore nie ciagna dex_analyzer ani manifest_parser — wyciszamy tu tez.
logger.disable("androguard")

from androguard.core.apk import APK


def _pobierz_cert_der(apk: APK):
    """Zwraca (DER certyfikatu, uzyty schemat podpisu) albo (None, None).

    Kaskada v1 -> v2 -> v3. get_signature_names()/get_certificate_der() czytaja
    wylacznie podpis JAR (META-INF/*.RSA), czyli schemat v1. APK budowane pod
    SDK 30+ czesto pomijaja v1 i maja tylko APK Signature Scheme v2/v3 — dla
    nich stary kod zwracal "No signature found (unsigned APK)", co bylo mylace
    i wylaczalo klastrowanie kampanii po certyfikacie.

    Kolejnosc jest celowa: v1 najpierw, zeby odciski juz zapisane w bazie
    pozostaly stabilne. Przy rotacji klucza (v3) v2 trzyma starszy certyfikat,
    ktory lepiej nadaje sie do korelacji historycznej.
    """
    try:
        nazwy = apk.get_signature_names()
        if nazwy:
            der = apk.get_certificate_der(nazwy[0])
            if der:
                return der, "v1"
    except Exception:
        pass

    for schemat, metoda in (("v2", "get_certificates_der_v2"),
                            ("v3", "get_certificates_der_v3")):
        try:
            dery = getattr(apk, metoda)()
        except Exception:
            continue
        if dery:
            return dery[0], schemat

    return None, None


def analyze_cert(apk: APK) -> dict:
    try:
        cert_der, schemat = _pobierz_cert_der(apk)
        if not cert_der:
            return {"error": "Brak podpisu (APK niepodpisany lub schemat nieobslugiwany)"}

        from asn1crypto import x509
        cert = x509.Certificate.load(cert_der)
        tbs = cert["tbs_certificate"]

        issuer_str = tbs["issuer"].human_friendly
        subject_str = tbs["subject"].human_friendly

        not_before = tbs["validity"]["not_before"].native
        not_after = tbs["validity"]["not_after"].native

        self_signed = issuer_str == subject_str

        sha1 = hashlib.sha1(cert_der).hexdigest().upper()
        sha256 = hashlib.sha256(cert_der).hexdigest().upper()

        now = datetime.datetime.now(datetime.timezone.utc)
        expired = not_after < now if not_after else None

        return {
            "subject": subject_str,
            "issuer": issuer_str,
            "self_signed": self_signed,
            "valid_from": not_before.isoformat() if not_before else None,
            "valid_to": not_after.isoformat() if not_after else None,
            "expired": expired,
            "sha1": sha1,
            "sha256": sha256,
            "signature_scheme": schemat,
        }

    except Exception as e:
        return {"error": str(e)}
