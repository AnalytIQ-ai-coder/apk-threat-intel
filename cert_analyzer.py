import datetime
import hashlib

from androguard.core.apk import APK


def analyze_cert(apk: APK) -> dict:
    try:
        sig_names = apk.get_signature_names()
        if not sig_names:
            return {"error": "No signature found (unsigned APK)"}

        cert_der = apk.get_certificate_der(sig_names[0])
        if not cert_der:
            return {"error": "Could not read certificate"}

        # Parse with asn1crypto
        from asn1crypto import pem, x509
        cert = x509.Certificate.load(cert_der)
        tbs = cert["tbs_certificate"]

        subject = dict(tbs["subject"].human_friendly.split(", ")[i].split("=", 1)
                       for i in range(len(tbs["subject"].human_friendly.split(", ")))
                       if "=" in tbs["subject"].human_friendly.split(", ")[i])

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
        }

    except Exception as e:
        return {"error": str(e)}
