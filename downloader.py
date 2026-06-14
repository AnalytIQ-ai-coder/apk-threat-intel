import os


def save_apk(obj, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    sha256 = getattr(obj, "sha256", None) or "unknown"
    filename = getattr(obj, "name", None) or f"{sha256}.apk"
    file_path = os.path.join(output_dir, filename)

    if os.path.exists(file_path):
        return file_path

    data = obj.download()

    with open(file_path, "wb") as f:
        f.write(data)

    return file_path
