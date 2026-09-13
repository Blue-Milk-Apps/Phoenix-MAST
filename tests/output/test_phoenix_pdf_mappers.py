from adapters.output.phoenix_report.pdf_report.ios import map_ios_binary_details
from domain.report import (
    AppDetails,
    EndpointDetails,
    FileDetails,
    FunctionalityDetails,
    HardcodedValuesDetails,
    IOSBinaryEvidenceDetails,
    IOSBinaryReportDetails,
    IOSSDKCategoryDetails,
    IOSUrlSchemeDetails,
    PermissionDetails,
)


def test_ios_binary_mapper_preserves_typed_inventory() -> None:
    details = IOSBinaryReportDetails(
        file_info=FileDetails(filename="Example.ipa"),
        app_info=AppDetails(name="Example"),
        binary_evidence=IOSBinaryEvidenceDetails(nx=True),
        url_schemes=(IOSUrlSchemeDetails("example", ("example",)),),
        functionality=(FunctionalityDetails("Camera", True, "detected"),),
        third_party_sdks=(IOSSDKCategoryDetails("Analytics", ("SDK",)),),
        permissions=(PermissionDetails("camera"),),
        hardcoded_values=HardcodedValuesDetails(),
        endpoints=(EndpointDetails("https://example.com"),),
    )
    mapped = map_ios_binary_details(details)
    assert mapped["file_info"]["filename"] == "Example.ipa"
    assert mapped["ipa_binary_protections"][0]["status"] == "Present"
    assert mapped["url_schemes"][0]["url_name"] == "example"
    assert mapped["functionality"]["Camera"]["present"] is True
    assert mapped["third_party_sdks"]["Analytics"]["SDK"] is True
    assert mapped["endpoints"][0]["endpoint"] == "https://example.com"
