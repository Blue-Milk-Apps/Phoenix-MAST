"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from domain.post_scan.android.app_certificate_builder import AppCertificateBuilder
from domain.post_scan.android.app_component_builder import AppComponentBuilder
from domain.post_scan.android.app_info_builder import AndroidAppInfoBuilder
from domain.post_scan.android.application_builder import ApplicationBuilder
from domain.post_scan.android.code_evidence import CodeEvidence
from domain.post_scan.android.data_storage_evidence import DataStorageEvidence
from domain.post_scan.android.deep_links_builder import DeepLinksBuilder
from domain.post_scan.android.endpoints_builder import EndpointsBuilder
from domain.post_scan.android.file_info_builder import FileInfoBuilder
from domain.post_scan.android.functionality_builder import FunctionalityBuilder
from domain.post_scan.android.hardcoded_values_builder import HardcodedValuesBuilder
from domain.post_scan.android.meta import AndroidMeta
from domain.post_scan.android.network_evidence import NetworkEvidence
from domain.post_scan.android.permissions_builder import PermissionsBuilder
from domain.post_scan.android.resilience_evidence import ResilienceEvidence
from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    ROOT_DETECTION_PATTERN = re.compile(r"(?i)(?:\bsu\b|busybox|supersu|magisk|test-keys|rootbeer|isrooted|rootcheck)")

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        app_info = AndroidAppInfoBuilder(loaded_outputs)
        application = ApplicationBuilder(loaded_outputs)
        app_components = AppComponentBuilder(loaded_outputs)
        certificate = AppCertificateBuilder(loaded_outputs)
        code_evidence = CodeEvidence(loaded_outputs, app_components, application, app_info)
        file_info = FileInfoBuilder(loaded_outputs)
        permissions = PermissionsBuilder(loaded_outputs).items
        functionality = FunctionalityBuilder(loaded_outputs).items
        resilience_evidence = ResilienceEvidence(loaded_outputs)
        deeplink_builder = DeepLinksBuilder(loaded_outputs)
        hardcoded_values = HardcodedValuesBuilder(loaded_outputs)
        meta = AndroidMeta(loaded_outputs)
        network_evidence = NetworkEvidence(loaded_outputs, hardcoded_values)
        data_storage_evidence = DataStorageEvidence(loaded_outputs, hardcoded_values)
        endpoints = EndpointsBuilder(loaded_outputs).items

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
            "deep_links": asdict(deeplink_builder),
            "hardcoded_values": asdict(hardcoded_values),
            "endpoints": endpoints,
        }
