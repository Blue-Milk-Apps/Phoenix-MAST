"""Map typed iOS binary details to Phoenix PDF presentation data."""

from __future__ import annotations

from dataclasses import asdict

from adapters.output.phoenix_report.pdf_report.common import map_functionality
from domain.report import IOSBinaryReportDetails


def _protection_description(name: str, detected: bool) -> str:
    match name:
        case "nx":
            return (
                "Non-executable memory is enabled, making injected data harder to execute as code."
                if detected
                else "Non-executable memory was not detected, increasing the impact of memory-corruption attacks."
            )
        case "pie":
            return (
                "Position-independent execution is enabled, allowing ASLR to randomize the binary's load address."
                if detected
                else "Position-independent execution was not detected, limiting ASLR and making code addresses predictable."
            )
        case "stack_canary":
            return (
                "Stack canaries are present and can detect stack-buffer corruption before control flow is hijacked."
                if detected
                else "Stack canaries were not detected, reducing protection against stack-buffer overflows."
            )
        case "arc":
            return (
                "Automatic Reference Counting is enabled, reducing memory-management errors such as dangling references."
                if detected
                else "Automatic Reference Counting was not detected, increasing reliance on error-prone manual memory management."
            )
        case "rpath":
            return (
                "Runtime library search paths are present and should resolve only to trusted, non-writable locations to prevent library hijacking."
                if detected
                else "No runtime library search paths were detected; RPATH is not itself a protection, but unsafe paths can enable library hijacking."
            )
        case "code_signature":
            return (
                "A code signature is present, enabling iOS to verify the binary's origin and integrity before execution."
                if detected
                else "A code signature was not detected, so the binary's origin and integrity cannot be verified."
            )
        case "encrypted":
            return (
                "The executable is encrypted, increasing the effort required to inspect or reverse engineer its code at rest."
                if detected
                else "Executable encryption was not detected, making static inspection and reverse engineering easier."
            )
        case "symbols_stripped":
            return (
                "Debug symbols are stripped, exposing less internal naming information to reverse engineers."
                if detected
                else "Debug symbols were not stripped, revealing internal names that can accelerate reverse engineering."
            )
        case _:
            return "Protection detected." if detected else "Protection not detected."


def map_ios_binary_details(details: IOSBinaryReportDetails) -> dict[str, object]:
    """Return template-shaped iOS binary inventory data."""

    return {
        "file_info": asdict(details.file_info),
        "app_info": asdict(details.app_info),
        "ipa_binary_protections": [
            {
                "protection": name.replace("_", " ").title(),
                "status": "Present" if value else "Not Present",
                "severity": "Info" if value else "Medium",
                "description": _protection_description(name, value),
            }
            for name, value in asdict(details.binary_evidence).items()
            if value is not None
        ],
        "url_schemes": [asdict(item) for item in details.url_schemes],
        "functionality": map_functionality(details.functionality),
        "third_party_sdks": {
            item.category: {name: True for name in item.sdk_names} for item in details.third_party_sdks
        },
        "permissions": [asdict(item) for item in details.permissions],
        "hardcoded_values": asdict(details.hardcoded_values),
        "endpoints": [asdict(item) for item in details.endpoints],
    }
