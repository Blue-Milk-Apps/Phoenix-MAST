"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.android.app_certificate import AppCertificate
from domain.post_scan.android.app_component import AppComponent
from domain.post_scan.android.app_info import AndroidAppInfo
from domain.post_scan.android.application import Application
from domain.post_scan.android.deep_links import DeepLinks
from domain.post_scan.android.endpoints import Endpoints
from domain.post_scan.android.file_info import FileInfo
from domain.post_scan.android.meta import AndroidMeta
from domain.post_scan.android.permissions import Permissions
from domain.post_scan.rule_assessment import RuleFunctionality, assessments_from_outputs
from domain.post_scan.utilities import secret_values
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        app_info = AndroidAppInfo(loaded_outputs)
        application = Application(loaded_outputs)
        app_components = AppComponent(loaded_outputs)
        certificate = AppCertificate(loaded_outputs)
        file_info = FileInfo(loaded_outputs)
        permissions = Permissions(loaded_outputs).items
        deep_links = DeepLinks(loaded_outputs)
        meta = AndroidMeta(loaded_outputs)
        endpoints = Endpoints(loaded_outputs).items

        return {
            "meta": asdict(meta),
            "app_info": asdict(app_info),
            "application": asdict(application),
            "app_components": asdict(app_components),
            "certificate": asdict(certificate),
            "file_info": asdict(file_info),
            "permissions": permissions,
            "functionality": RuleFunctionality(
                loaded_outputs.get("opengrep"), assessments=assessments_from_outputs(loaded_outputs)
            ).items,
            "deep_links": asdict(deep_links),
            "hardcoded_values": secret_values(loaded_outputs),
            "endpoints": endpoints,
        }
