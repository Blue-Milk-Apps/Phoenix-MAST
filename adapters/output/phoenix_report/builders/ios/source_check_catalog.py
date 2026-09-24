"""Checks backed by structured scanners; OpenGrep content comes from YAML."""

from adapters.output.phoenix_report.builders.source import SourceCheckDefinition
from domain.report import CheckSeverity

IOS_SOURCE_SECTION_CHECKS = (
    (
        "Code",
        "code_evidence",
        (
            SourceCheckDefinition(
                name="Insecure Nanopb Library",
                evidence_key="insecure_nanopb_library",
                severity=CheckSeverity.HIGH,
                compliance="MASVS-CODE-3; legacy MSTG-CODE-3 (as observed)",
                present_explanation="App bundles a known-vulnerable version of the Nanopb protobuf library.",
                not_present_explanation="App does not bundle a known-vulnerable version of the Nanopb protobuf library.",
            ),
            SourceCheckDefinition(
                name="Hardcoded API Keys within the Application Bundle",
                evidence_key="hardcoded_api_keys_in_bundle",
                severity=CheckSeverity.HIGH,
                compliance="MASVS-CRYPTO-2, MASVS-STORAGE-1; legacy MSTG-CRYPTO-2",
                present_explanation="A hardcoded API key was found bundled in the app package.",
                not_present_explanation="No hardcoded API keys were found bundled in the app package.",
            ),
            SourceCheckDefinition(
                name="Potentially Insecure iOS Entitlements",
                evidence_key="insecure_entitlements",
                severity=CheckSeverity.MEDIUM,
                compliance="MASVS-PLATFORM-1, MASVS-RESILIENCE-2; legacy MSTG-PLATFORM-1",
                present_explanation="One or more entitlements are flagged as risky (e.g. broadly-shared keychain-access-groups, get-task-allow enabled in a production build).",
                not_present_explanation="No entitlements flagged as risky (e.g. broadly-shared keychain-access-groups, get-task-allow enabled in a production build) were found.",
            ),
        ),
    ),
)
