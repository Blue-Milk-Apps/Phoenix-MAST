from domain.post_scan.ios.binary.resilience_evidence import IOSResilienceEvidence


def test_ios_resilience_evidence_requires_manual_review_without_authentication_evidence() -> None:
    evidence = IOSResilienceEvidence({})

    assert evidence.biometric_bypass_possible.present is None
    assert evidence.biometric_bypass_possible.evidence == (
        "source_control_flow_and_runtime_authentication_testing_required"
    )
    assert evidence.debug_symbols_present.present is False
    assert evidence.debug_symbols_present.evidence == "no_debug_symbols_present_hits"
