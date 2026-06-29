from pathlib import Path
import base64
Path("images").mkdir(exist_ok=True)
png_data = Path("images/imm.png").read_bytes()
png_data += b"\nSUSPICIOUS\n"
