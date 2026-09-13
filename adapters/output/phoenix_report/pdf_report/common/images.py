"""Image data URI helpers shared by PDF report adapters."""

import base64
from pathlib import Path

ASSETS_DIR = Path(__file__).parents[2] / "assets"
PLACEHOLDER_ICON_PATH = ASSETS_DIR / "placeholder_icon.png"
REPORT_BRAND_ICON_PATH = ASSETS_DIR / "PhoenixShield.png"


def _image_file_to_data_uri(target: Path) -> str:
    extension = target.suffix.lstrip(".").lower() or "png"
    mime = "jpeg" if extension in ("jpg", "jpeg") else extension
    return f"data:image/{mime};base64,{base64.b64encode(target.read_bytes()).decode('ascii')}"


def get_app_icon_data_uri(data: dict[str, object]) -> str:
    app_info = data.get("app_info")
    icon_path = app_info.get("icon_path") if isinstance(app_info, dict) else None
    target = Path(icon_path) if isinstance(icon_path, str) and icon_path else PLACEHOLDER_ICON_PATH
    return _image_file_to_data_uri(target if target.is_file() else PLACEHOLDER_ICON_PATH)


def get_report_brand_icon_data_uri() -> str:
    return _image_file_to_data_uri(
        REPORT_BRAND_ICON_PATH if REPORT_BRAND_ICON_PATH.is_file() else PLACEHOLDER_ICON_PATH
    )
