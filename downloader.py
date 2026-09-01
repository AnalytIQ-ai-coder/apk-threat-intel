import os
import re


def save_apk(obj, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    sha256 = getattr(obj, "sha256", None) or "unknown"

    # obj.name to oryginalna nazwa nadana przez osobę wrzucającą próbkę do MWDB,
    # czyli wartość kontrolowana przez potencjalnego atakującego. Użyta wprost
    # w os.path.join pozwala wyjść poza output/ (np. "..\\..\\Windows\\..."),
    # dlatego zapisujemy zawsze pod zwalidowanym hashem.
    if not re.fullmatch(r'[0-9a-fA-F]{64}', str(sha256)):
        raise ValueError(f"Nieprawidłowy SHA256 próbki: {sha256!r}")

    file_path = os.path.abspath(os.path.join(output_dir, f"{sha256.lower()}.apk"))

    if os.path.exists(file_path):
        return file_path

    data = obj.download()

    with open(file_path, "wb") as f:
        f.write(data)

    return file_path
