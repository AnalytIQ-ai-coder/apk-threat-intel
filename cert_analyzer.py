"""Signing-certificate extraction and summary.

Certificates are the backbone of campaign clustering here: one key reused
across dozens of packages is usually a stronger signal than anything in the
DEX, because the operator has to re-sign every build.
"""
import datetime
import hashlib

from loguru import logger

# This module gets imported on its own by small tooling scripts that never
# touch dex_analyzer or manifest_parser, so the muting has to happen here too.
logger.disable("androguard")

from androguard.core.apk import APK  # noqa: E402


def extract_cert_der(apk: APK):
    """Return (certificate DER, signature scheme used) or (None, None).

    Falls through v1 -> v2 -> v3. get_signature_names()/get_certificate_der()
    only ever look at the JAR signature (META-INF/*.RSA), i.e. scheme v1. APKs
    built for SDK 30+ often skip v1 entirely and ship only APK Signature Scheme
    v2/v3; for those the old code reported "No signature found (unsigned APK)",
    which was both wrong and quietly disabled cert-based clustering.

    The order matters: v1 first so fingerprints already in the database stay
    stable. After a key rotation (v3) it is v2 that still carries the older
    certificate, which is the more useful one for historical correlation.
    """
    try:
        names = apk.get_signature_names()
        if names:
            der = apk.get_certificate_der(names[0])
            if der:
                return der, "v1"
    except Exception:
        pass

    for scheme, method in (("v2", "get_certificates_der_v2"),
                           ("v3", "get_certificates_der_v3")):
        try:
            ders = getattr(apk, method)()
        except Exception:
            continue
        if ders:
            return ders[0], scheme

    return None, None


def analyze_cert(apk: APK) -> dict:
    """Summarise the signing certificate: subject, validity, fingerprints."""
    try:
        cert_der, scheme = extract_cert_der(apk)
        if not cert_der:
            return {"error": "No signature (unsigned APK or unsupported scheme)"}

        from asn1crypto import x509
        cert = x509.Certificate.load(cert_der)
        tbs = cert["tbs_certificate"]

        issuer_str = tbs["issuer"].human_friendly
        subject_str = tbs["subject"].human_friendly

        not_before = tbs["validity"]["not_before"].native
        not_after = tbs["validity"]["not_after"].native

        now = datetime.datetime.now(datetime.timezone.utc)

        return {
            "subject": subject_str,
            "issuer": issuer_str,
            "self_signed": issuer_str == subject_str,
            "valid_from": not_before.isoformat() if not_before else None,
            "valid_to": not_after.isoformat() if not_after else None,
            "expired": not_after < now if not_after else None,
            "sha1": hashlib.sha1(cert_der).hexdigest().upper(),
            "sha256": hashlib.sha256(cert_der).hexdigest().upper(),
            "signature_scheme": scheme,
        }

    except Exception as e:
        return {"error": str(e)}
