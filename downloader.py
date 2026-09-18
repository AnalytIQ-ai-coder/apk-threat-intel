"""Save a sample from MWDB to disk under a name we control."""
import os
import re


def save_apk(obj, output_dir="output"):
    """Write the sample to output_dir as <sha256>.apk and return the path.

    Returns immediately if the file is already there.
    """
    os.makedirs(output_dir, exist_ok=True)

    sha256 = getattr(obj, "sha256", None) or "unknown"

    # obj.name is whatever the uploader typed into MWDB, so an attacker controls
    # it. Handed straight to os.path.join it could escape output/ entirely
    # (think "..\\..\\Windows\\..."), so we always write under the validated
    # hash instead.
    if not re.fullmatch(r'[0-9a-fA-F]{64}', str(sha256)):
        raise ValueError(f"Malformed sample SHA-256: {sha256!r}")

    file_path = os.path.abspath(os.path.join(output_dir, f"{sha256.lower()}.apk"))

    if os.path.exists(file_path):
        return file_path

    data = obj.download()

    with open(file_path, "wb") as f:
        f.write(data)

    return file_path
