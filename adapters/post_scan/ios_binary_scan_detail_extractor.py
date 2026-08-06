"""iOS binary detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.ios.app_info_builder import IOSAppInfo
from domain.post_scan.ios.code_evidence_builder import IOSCodeEvidence
from domain.post_scan.ios.data_storage_evidence_builder import IOSDataStorageEvidence
from domain.post_scan.ios.endpoints_builder import IOSEndpoints
from domain.post_scan.ios.file_info import IOSFileInfo
from domain.post_scan.ios.functionality_builder import IOSFunctionality
from domain.post_scan.ios.hardcoded_values_builder import IOSHardcodedValues
from domain.post_scan.ios.ipa_binary_evidence_builder import IOSIPABinaryEvidence
from domain.post_scan.ios.meta_builder import IOSMeta
from domain.post_scan.ios.network_evidence_builder import IOSNetworkEvidence
from domain.post_scan.ios.permissions_builder import IOSPermissions
from domain.post_scan.ios.resilience_evidence_builder import IOSResilienceEvidence
from domain.post_scan.ios.third_party_sdks_builder import IOSThirdPartySDKs
from domain.post_scan.ios.url_schemes_builder import IOSURLSchemes
from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class IOSBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract iOS-binary-specific sections from loaded scan outputs."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        functionality_model = asdict(IOSFunctionality(loaded_outputs))
        functionality = {
            "Camera": functionality_model["Camera"],
            "Biometric Authentication": functionality_model["Biometric_Authentication"],
            "Networking": functionality_model["Networking"],
            "Secure RNG": functionality_model["Secure_RNG"],
            "Push Notifications": functionality_model["Push_Notifications"],
            "Audio": functionality_model["Audio"],
            "Contacts": functionality_model["Contacts"],
            "Geofencing": functionality_model["Geofencing"],
            "Health Data": functionality_model["Health_Data"],
            "Location": functionality_model["Location"],
            "Maps": functionality_model["Maps"],
            "Payment Services": functionality_model["Payment_Services"],
            "SMS": functionality_model["SMS"],
            "Bluetooth": functionality_model["Bluetooth"],
            "Camera Delegation": functionality_model["Camera_Delegation"],
            "Calendar": functionality_model["Calendar"],
            "In-App Purchases": functionality_model["In_App_Purchases"],
            "Keychain": functionality_model["Keychain"],
            "Microphone": functionality_model["Microphone"],
            "NFC": functionality_model["NFC"],
            "Photos": functionality_model["Photos"],
            "Sensors": functionality_model["Sensors"],
            "Telephony": functionality_model["Telephony"],
            "USB Devices": functionality_model["USB_Devices"],
            "Nearby Interaction": functionality_model["Nearby_Interaction"],
        }
        third_party_sdks_model = asdict(IOSThirdPartySDKs(loaded_outputs))
        third_party_sdks = {
            "Analytics": third_party_sdks_model["Analytics"],
            "Advertising": third_party_sdks_model["Advertising"],
            "Cloud Storage": third_party_sdks_model["Cloud_Storage"],
            "Developer Tools": third_party_sdks_model["Developer_Tools"],
        }
        ipa_binary_evidence = IOSIPABinaryEvidence(loaded_outputs)

        return {
            "meta": asdict(IOSMeta(loaded_outputs)),
            "file_info": asdict(IOSFileInfo(loaded_outputs)),
            "app_info": asdict(IOSAppInfo(loaded_outputs)),
            "ipa_binary_evidence": {
                "nx": ipa_binary_evidence.nx,
                "pie": ipa_binary_evidence.pie,
                "stack canary": ipa_binary_evidence.stack_canary,
                "arc": ipa_binary_evidence.arc,
                "rpath": ipa_binary_evidence.rpath,
                "code signature": ipa_binary_evidence.code_signature,
                "encrypted": ipa_binary_evidence.encrypted,
                "symbols stripped": ipa_binary_evidence.symbols_stripped,
            },
            "url_schemes": IOSURLSchemes(loaded_outputs).items,
            "functionality": functionality,
            "third_party_sdks": third_party_sdks,
            "permissions": IOSPermissions(loaded_outputs).items,
            "code_evidence": asdict(IOSCodeEvidence(loaded_outputs)),
            "network_evidence": asdict(IOSNetworkEvidence(loaded_outputs)),
            "data_storage_evidence": asdict(IOSDataStorageEvidence(loaded_outputs)),
            "resilience_evidence": asdict(IOSResilienceEvidence(loaded_outputs)),
            "hardcoded_values": asdict(IOSHardcodedValues(loaded_outputs)),
            "endpoints": IOSEndpoints(loaded_outputs).items,
        }
