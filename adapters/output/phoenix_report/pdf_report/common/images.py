"""Image data URI helpers shared by PDF report adapters."""

import base64
import binascii
import io
from pathlib import Path

from PIL import Image

ASSETS_DIR = Path(__file__).parents[2] / "assets"
PLACEHOLDER_ICON_PATH = ASSETS_DIR / "placeholder_icon.png"
REPORT_BRAND_ICON_PATH = ASSETS_DIR / "PhoenixShield.png"


def _image_file_to_data_uri(target: Path) -> str:
    extension = target.suffix.lstrip(".").lower() or "png"
    mime = "jpeg" if extension in ("jpg", "jpeg") else extension
    return f"data:image/{mime};base64,{base64.b64encode(target.read_bytes()).decode('ascii')}"


def get_app_icon_data_uri(data: dict[str, object]) -> str:
    app_info = data.get("app_info")
    embedded_icon = app_info.get("icon_data_uri") if isinstance(app_info, dict) else None
    if isinstance(embedded_icon, str) and embedded_icon.startswith(
        ("data:image/png;base64,", "data:image/jpeg;base64,")
    ):
        try:
            image_bytes = base64.b64decode(embedded_icon.split(",", 1)[1], validate=True)
            with Image.open(io.BytesIO(image_bytes)) as image:
                image.verify()
            return embedded_icon
        except (ValueError, OSError, binascii.Error, Image.DecompressionBombError):
            pass
    icon_path = app_info.get("icon_path") if isinstance(app_info, dict) else None
    if isinstance(icon_path, str) and icon_path:
        try:
            target = Path(icon_path)
            with Image.open(target) as image:
                image.verify()
            return _image_file_to_data_uri(target)
        except (ValueError, OSError, Image.DecompressionBombError):
            pass
    return _image_file_to_data_uri(PLACEHOLDER_ICON_PATH)


def get_report_brand_icon_data_uri() -> str:
    return _image_file_to_data_uri(
        REPORT_BRAND_ICON_PATH if REPORT_BRAND_ICON_PATH.is_file() else PLACEHOLDER_ICON_PATH
    )
