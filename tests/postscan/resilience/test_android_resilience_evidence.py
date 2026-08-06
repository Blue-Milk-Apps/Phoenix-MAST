from domain.post_scan.android.resilience_evidence_builder import ResilienceEvidenceBuilder


def test_android_resilience_evidence_detects_root_checks_and_biometric_hardening() -> None:
    loaded_outputs = {
        "aapt2_identity": {"package_name": "com.example.app"},
        "androguard_api_calls": {
            "items": [
                {
                    "callee": {"signature": "Lcom/scottyab/rootbeer/RootBeer; isRooted ()Z"},
                    "caller": {"signature": "Lcom/example/app/Security; checkRoot ()Z"},
                },
                {
                    "callee": {"signature": "Landroidx/biometric/BiometricPrompt; authenticate ()V"},
                    "caller": {"signature": "Lcom/example/app/Login; authenticate ()V"},
                },
                {
                    "callee": {
                        "signature": "Landroid/security/keystore/KeyGenParameterSpec; setUserAuthenticationRequired (Z)V"
                    },
                    "caller": {"signature": "Lcom/example/app/Login; authenticate ()V"},
                },
            ]
        },
    }

    evidence = ResilienceEvidenceBuilder(loaded_outputs)

    assert evidence.root_detection_missing == {
        "present": False,
        "evidence": "Lcom/example/app/Security; checkRoot ()Z",
        "details": ["Lcom/example/app/Security; checkRoot ()Z"],
    }
    assert evidence.biometric_local_authentication_bypass_possible == {
        "present": False,
        "evidence": "Lcom/example/app/Login; authenticate ()V",
        "details": ["Lcom/example/app/Login; authenticate ()V"],
    }


def test_android_resilience_evidence_reports_missing_root_detection() -> None:
    evidence = ResilienceEvidenceBuilder({"aapt2_identity": {"package_name": "com.example.app"}})

    assert evidence.root_detection_missing == {
        "present": True,
        "evidence": "no_root_detection_signals_found",
        "details": [],
    }
    assert evidence.biometric_local_authentication_bypass_possible == {
        "present": False,
        "evidence": "no_biometric_authentication_flow_detected",
    }
