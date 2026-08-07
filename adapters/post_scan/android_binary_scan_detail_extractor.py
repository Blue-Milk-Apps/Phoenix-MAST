"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from domain.post_scan.android.app_certificate import AppCertificate
from domain.post_scan.android.app_component import AppComponent
from domain.post_scan.android.app_info import AndroidAppInfo
from domain.post_scan.android.application import Application
from domain.post_scan.android.code_evidence import CodeEvidence
from domain.post_scan.android.data_storage_evidence import DataStorageEvidence
from domain.post_scan.android.deep_links import DeepLinks
from domain.post_scan.android.endpoints import Endpoints
from domain.post_scan.android.file_info import FileInfo
from domain.post_scan.android.functionality import Functionality
from domain.post_scan.android.hardcoded_values import HardcodedValues
from domain.post_scan.android.meta import AndroidMeta
from domain.post_scan.android.network_evidence import NetworkEvidence
from domain.post_scan.android.permissions import Permissions
from domain.post_scan.android.resilience_evidence import ResilienceEvidence
from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    ROOT_DETECTION_PATTERN = re.compile(r"(?i)(?:\bsu\b|busybox|supersu|magisk|test-keys|rootbeer|isrooted|rootcheck)")

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        app_info = AndroidAppInfo(loaded_outputs)
        application = Application(loaded_outputs)
        app_components = AppComponent(loaded_outputs)
        certificate = AppCertificate(loaded_outputs)
        code_evidence = CodeEvidence(loaded_outputs, app_components, application, app_info)
        file_info = FileInfo(loaded_outputs)
        permissions = Permissions(loaded_outputs).items
        functionality = Functionality(loaded_outputs).items
        resilience_evidence = ResilienceEvidence(loaded_outputs)
        deep_links = DeepLinks(loaded_outputs)
        hardcoded_values = HardcodedValues(loaded_outputs)
        meta = AndroidMeta(loaded_outputs)
        network_evidence = NetworkEvidence(loaded_outputs, hardcoded_values)
        data_storage_evidence = DataStorageEvidence(loaded_outputs, hardcoded_values)
        endpoints = Endpoints(loaded_outputs).items

        return {
            "meta": asdict(meta),
            "app_info": asdict(app_info),
            "application": asdict(application),
            "app_components": asdict(app_components),
            "certificate": asdict(certificate),
            "code_evidence": asdict(code_evidence),
            "file_info": asdict(file_info),
            "permissions": permissions,
            "functionality": functionality,
            "network_evidence": asdict(network_evidence),
            "resilience_evidence": asdict(resilience_evidence),
            "data_storage_evidence": asdict(data_storage_evidence),
            "deep_links": asdict(deep_links),
            "hardcoded_values": asdict(hardcoded_values),
            "endpoints": endpoints,
        }
