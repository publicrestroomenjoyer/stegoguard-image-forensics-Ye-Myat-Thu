from pathlib import Path
import sys

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_END = b"\x00\x00\x00\x00IEND\xaeB`\x82"

JPEG_SIGNATURE = b"\xff\xd8\xff"
JPEG_END = b"\xff\xd9"

GIF_SIGNATURES = [b"GIF87a", b"GIF89a"]
GIF_END = b"\x3b"

SUSPICIOUS_WORDS = [
    b"hidden_message",
    b"secret",
    b"password",
    b"token",
    b"api_key",
    b"confidential",
]


def scan_image(path):
    data = path.read_bytes()
    issues = []
    suffix = path.suffix.lower()

    if suffix == ".png":
        if not data.startswith(PNG_SIGNATURE):
            issues.append("File extension is PNG, but PNG signature is missing.")

        end_position = data.rfind(PNG_END)
        if end_position == -1:
            issues.append("PNG ending marker was not found.")
        else:
            real_end = end_position + len(PNG_END)
            extra_data = data[real_end:]
            if extra_data.strip():
                issues.append(f"Extra data found after PNG ending marker: {len(extra_data)} bytes.")

    elif suffix in [".jpg", ".jpeg"]:
        if not data.startswith(JPEG_SIGNATURE):
            issues.append("File extension is JPG/JPEG, but JPEG signature is missing.")

        end_position = data.rfind(JPEG_END)
        if end_position == -1:
            issues.append("JPEG ending marker was not found.")
        else:
            real_end = end_position + len(JPEG_END)
            extra_data = data[real_end:]
            if extra_data.strip():
                issues.append(f"Extra data found after JPEG ending marker: {len(extra_data)} bytes.")

    elif suffix == ".gif":
        if not any(data.startswith(sig) for sig in GIF_SIGNATURES):
            issues.append("File extension is GIF, but GIF signature is missing.")

        end_position = data.rfind(GIF_END)
        if end_position == -1:
            issues.append("GIF ending marker was not found.")
        else:
            real_end = end_position + len(GIF_END)
            extra_data = data[real_end:]
            if extra_data.strip():
                issues.append(f"Extra data found after GIF ending marker: {len(extra_data)} bytes.")

    else:
        return []

    lower_data = data.lower()
    for word in SUSPICIOUS_WORDS:
        if word in lower_data:
            issues.append(f"Suspicious keyword found inside file: {word.decode()}")

    return issues


def main():
    image_folder = Path("images")

    if not image_folder.exists():
        print("No images folder found.")
        return 0

    image_files = []
    for extension in ["*.png", "*.jpg", "*.jpeg", "*.gif"]:
        image_files.extend(image_folder.glob(extension))

    if not image_files:
        print("No image files found.")
        return 0

    suspicious_found = False

    for image in sorted(image_files):
        print(f"\nScanning: {image}")
        issues = scan_image(image)

        if issues:
            suspicious_found = True
            print("Status: SUSPICIOUS")
            for issue in issues:
                print(f"- {issue}")
        else:
            print("Status: CLEAN")
            print("- No suspicious appended data detected.")

    if suspicious_found:
        print("\nStegoGuard result: FAILED")
        print("Suspicious image data was detected.")
        return 1

    print("\nStegoGuard result: PASSED")
    print("No suspicious image data detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
