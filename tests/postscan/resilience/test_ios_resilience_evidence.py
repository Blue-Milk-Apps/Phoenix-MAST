from domain.post_scan.ios.resilience_evidence import IOSResilienceEvidence


def test_ios_resilience_evidence_returns_default_binary_assessment() -> None:
    evidence = IOSResilienceEvidence({})

    assert evidence.biometric_bypass_possible.present is False
    assert evidence.biometric_bypass_possible.evidence == "no_biometric_bypass_possible_hits"
    assert evidence.debug_symbols_present.present is False
    assert evidence.debug_symbols_present.evidence == "no_debug_symbols_present_hits"
