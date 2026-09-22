from domain.post_scan.ios.common.data_storage_evidence import IOSDataStorageEvidence


def test_ios_data_storage_evidence_sensitive_values_requires_source_finding() -> None:
    detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.sensitive-value-insecure-storage",
                        "path": "Sources/Session.swift",
                        "extra": {
                            "lines": "accessToken.write(to: fileURL)",
                        },
                    }
                ]
            }
        }
    )
    assert detected.sensitive_values_stored_insecurely.present is True
    assert detected.sensitive_values_stored_insecurely.evidence == (
        "Sources/Session.swift: accessToken.write(to: fileURL)"
    )

    no_hit = IOSDataStorageEvidence({"opengrep": {"results": []}})
    assert no_hit.sensitive_values_stored_insecurely.present is False
    assert no_hit.sensitive_values_stored_insecurely.evidence == "no_sensitive_values_stored_insecurely_hits"

    binary_only = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "accessToken\nNSKeyedArchiver"}})
    assert binary_only.sensitive_values_stored_insecurely.present is None
    assert binary_only.sensitive_values_stored_insecurely.evidence == (
        "(Triage Signal; source review required) App.txt: token; NSKeyedArchiver"
    )


def test_ios_data_storage_evidence_wifi_ip_requires_source_finding() -> None:
    detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.wifi-ip-insecure-storage",
                        "path": "Sources/NetworkInfo.swift",
                        "extra": {
                            "lines": 'UserDefaults.standard.set(wifiIPAddress, forKey: "network_ip")',
                        },
                    }
                ]
            }
        }
    )
    assert detected.wifi_ip_stored_insecurely.present is True
    assert detected.wifi_ip_stored_insecurely.evidence == (
        'Sources/NetworkInfo.swift: UserDefaults.standard.set(wifiIPAddress, forKey: "network_ip")'
    )

    no_hit = IOSDataStorageEvidence({"opengrep": {"results": []}})
    assert no_hit.wifi_ip_stored_insecurely.present is False
    assert no_hit.wifi_ip_stored_insecurely.evidence == "no_wifi_ip_stored_insecurely_hits"

    binary_only = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "wifiIPAddress\nUserDefaults"}})
    assert binary_only.wifi_ip_stored_insecurely.present is None
    assert binary_only.wifi_ip_stored_insecurely.evidence == (
        "(Triage Signal; source review required) App.txt: wifiipaddress; UserDefaults"
    )


def test_ios_data_storage_evidence_includes_source_location_and_keychain_operation(tmp_path) -> None:
    source_path = tmp_path / "Credentials.swift"
    source_path.write_text(
        "let accessibility = kSecAttrAccessibleAfterFirstUnlock\nSecItemAdd(query, nil)\n",
        encoding="utf-8",
    )
    detected = IOSDataStorageEvidence(
        {
            "scan_metadata": {"project_path": str(tmp_path)},
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.keychain-items-accessible-after-first-unlock",
                        "path": str(source_path),
                        "start": {"line": 1},
                        "extra": {"lines": "let accessibility = kSecAttrAccessibleAfterFirstUnlock"},
                    }
                ]
            },
        }
    )

    assert detected.keychain_items_accessible_after_first_unlock.evidence == (
        f"{source_path}:1: let accessibility = kSecAttrAccessibleAfterFirstUnlock (Keychain operation: SecItemAdd)"
    )


def test_ios_data_storage_evidence_includes_wifi_dataflow_context() -> None:
    detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.wifi-mac-insecure-storage",
                        "path": "Sources/NetworkInfo.swift",
                        "start": {"line": 12},
                        "extra": {
                            "lines": 'UserDefaults.standard.set(wifiMac, forKey: "bssid")',
                            "metavars": {
                                "$VALUE": {"abstract_content": "bssid"},
                            },
                        },
                        "dataflow_trace": {
                            "intermediate_vars": [{"content": "wifiMac"}],
                            "taint_sink": ["CliLoc", [{}, 'UserDefaults.standard.set(wifiMac, forKey: "bssid")']],
                        },
                    }
                ]
            }
        }
    )

    assert detected.wifi_mac_stored_insecurely.evidence.endswith(
        "(Data flow: bssid -> wifiMac -> UserDefaults.standard.set)"
    )


def test_ios_data_storage_evidence_source_only_storage_checks_have_ipa_triage() -> None:
    cases = (
        (
            "location_data_stored_insecurely",
            "ios.storage.location-data-insecure-storage",
            "Sources/Location.swift",
            "location.coordinate.write(to: fileURL)",
            "CLLocation\nNSKeyedArchiver",
            "cllocation",
            "NSKeyedArchiver",
            "no_location_data_stored_insecurely_hits",
        ),
        (
            "hardcoded_api_keys_stored_insecurely",
            "ios.storage.hardcoded-api-key-insecure-storage",
            "Sources/Configuration.swift",
            'UserDefaults.standard.set("key", forKey: "api_key")',
            "api_key\nUserDefaults",
            "api_key",
            "UserDefaults",
            "no_hardcoded_api_keys_stored_insecurely_hits",
        ),
        (
            "hardcoded_passwords_stored_insecurely",
            "ios.storage.hardcoded-password-insecure-storage",
            "Sources/Configuration.swift",
            'UserDefaults.standard.set("password", forKey: "password")',
            "password\nUserDefaults",
            "password",
            "UserDefaults",
            "no_hardcoded_passwords_stored_insecurely_hits",
        ),
    )

    for field, rule_id, path, line, binary_text, data_marker, storage_marker, no_hit_evidence in cases:
        source_detected = IOSDataStorageEvidence(
            {"opengrep": {"results": [{"check_id": rule_id, "path": path, "extra": {"lines": line}}]}}
        )
        source_entry = getattr(source_detected, field)
        assert source_entry.present is True
        assert source_entry.evidence == f"{path}: {line}"

        binary_triage = IOSDataStorageEvidence({"strings_outputs": {"App.txt": binary_text}})
        binary_entry = getattr(binary_triage, field)
        assert binary_entry.present is None
        assert (
            binary_entry.evidence == f"(Triage Signal; source review required) App.txt: {data_marker}; {storage_marker}"
        )

        no_hit = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "settings"}})
        no_hit_entry = getattr(no_hit, field)
        assert no_hit_entry.present is None
        assert no_hit_entry.evidence == "source_data_flow_analysis_required"


def test_ios_data_storage_evidence_keychain_items_accessible_after_first_unlock() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.keychain-items-accessible-after-first-unlock",
                        "path": "Sources/Credentials.swift",
                        "extra": {
                            "lines": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
                        },
                    }
                ]
            }
        }
    )
    assert source_detected.keychain_items_accessible_after_first_unlock.present is True
    assert source_detected.keychain_items_accessible_after_first_unlock.evidence == (
        "Sources/Credentials.swift: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
    )

    binary_detected = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "kSecAttrAccessibleAfterFirstUnlock"}})
    assert binary_detected.keychain_items_accessible_after_first_unlock.present is True
    assert binary_detected.keychain_items_accessible_after_first_unlock.evidence == (
        "App.txt: kSecAttrAccessibleAfterFirstUnlock"
    )

    no_hit = IOSDataStorageEvidence({"opengrep": {"results": []}, "strings_outputs": {"App.txt": ""}})
    assert no_hit.keychain_items_accessible_after_first_unlock.present is False
    assert (
        no_hit.keychain_items_accessible_after_first_unlock.evidence
        == "no_keychain_items_accessible_after_first_unlock_hits"
    )


def test_ios_data_storage_evidence_sensitive_data_stored_in_user_defaults() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.sensitive-data-in-user-defaults",
                        "path": "Sources/Session.swift",
                        "extra": {
                            "lines": 'UserDefaults.standard.set(accessToken, forKey: "session")',
                        },
                    }
                ]
            }
        }
    )
    assert source_detected.sensitive_data_stored_in_user_defaults.present is True
    assert source_detected.sensitive_data_stored_in_user_defaults.evidence == (
        'Sources/Session.swift: UserDefaults.standard.set(accessToken, forKey: "session")'
    )

    source_no_hit = IOSDataStorageEvidence({"opengrep": {"results": []}})
    assert source_no_hit.sensitive_data_stored_in_user_defaults.present is False
    assert (
        source_no_hit.sensitive_data_stored_in_user_defaults.evidence
        == "no_sensitive_data_stored_in_user_defaults_hits"
    )

    binary_triage = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "UserDefaults\naccessToken"}})
    assert binary_triage.sensitive_data_stored_in_user_defaults.present is None
    assert (
        binary_triage.sensitive_data_stored_in_user_defaults.evidence
        == "(Triage Signal; source review required) App.txt: UserDefaults; token"
    )

    binary_no_hit = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "UserDefaults\nsettings"}})
    assert binary_no_hit.sensitive_data_stored_in_user_defaults.present is None
    assert binary_no_hit.sensitive_data_stored_in_user_defaults.evidence == "source_data_flow_analysis_required"


def test_ios_data_storage_evidence_advertiser_id_logged_insecurely() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.advertiser-id-logged-insecurely",
                        "path": "Sources/Analytics.swift",
                        "extra": {"lines": "print(advertisingIdentifier)"},
                    }
                ]
            }
        }
    )
    assert source_detected.advertiser_id_logged_insecurely.present is True
    assert (
        source_detected.advertiser_id_logged_insecurely.evidence
        == "Sources/Analytics.swift: print(advertisingIdentifier)"
    )

    binary_triage = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "NSLog\nadvertisingIdentifier"}})
    assert binary_triage.advertiser_id_logged_insecurely.present is None
    assert (
        binary_triage.advertiser_id_logged_insecurely.evidence
        == "(Triage Signal; source review required) App.txt: nslog; advertisingIdentifier"
    )

    no_hit = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "NSLog\nsettings"}})
    assert no_hit.advertiser_id_logged_insecurely.present is None
    assert no_hit.advertiser_id_logged_insecurely.evidence == "source_data_flow_analysis_required"


def test_ios_data_storage_evidence_imei_logged_insecurely() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.imei-logged-insecurely",
                        "path": "Sources/Diagnostics.swift",
                        "extra": {"lines": "debugPrint(deviceImei)"},
                    }
                ]
            }
        }
    )
    assert source_detected.imei_logged_insecurely.present is True
    assert source_detected.imei_logged_insecurely.evidence == "Sources/Diagnostics.swift: debugPrint(deviceImei)"

    binary_triage = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "os_log\ndeviceImei"}})
    assert binary_triage.imei_logged_insecurely.present is None
    assert binary_triage.imei_logged_insecurely.evidence == (
        "(Triage Signal; source review required) App.txt: os_log; deviceImei"
    )

    no_hit = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "os_log\ndeviceIdentifier"}})
    assert no_hit.imei_logged_insecurely.present is None
    assert no_hit.imei_logged_insecurely.evidence == "source_data_flow_analysis_required"


def test_ios_data_storage_evidence_location_data_logged_insecurely() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.location-data-logged-insecurely",
                        "path": "Sources/Location.swift",
                        "extra": {"lines": "print(location.coordinate)"},
                    }
                ]
            }
        }
    )
    assert source_detected.location_data_logged_insecurely.present is True
    assert (
        source_detected.location_data_logged_insecurely.evidence == "Sources/Location.swift: print(location.coordinate)"
    )

    binary_triage = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "Logger\nlatitude"}})
    assert binary_triage.location_data_logged_insecurely.present is None
    assert binary_triage.location_data_logged_insecurely.evidence == (
        "(Triage Signal; source review required) App.txt: logger; latitude"
    )

    no_hit = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "Logger\nsettings"}})
    assert no_hit.location_data_logged_insecurely.present is None
    assert no_hit.location_data_logged_insecurely.evidence == "source_data_flow_analysis_required"


def test_ios_data_storage_evidence_sensitive_data_logged_insecurely() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.sensitive-data-logged-insecurely",
                        "path": "Sources/Session.swift",
                        "extra": {"lines": "print(accessToken)"},
                    }
                ]
            }
        }
    )
    assert source_detected.sensitive_data_logged_insecurely.present is True
    assert source_detected.sensitive_data_logged_insecurely.evidence == "Sources/Session.swift: print(accessToken)"

    binary_triage = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "NSLog\naccessToken"}})
    assert binary_triage.sensitive_data_logged_insecurely.present is None
    assert binary_triage.sensitive_data_logged_insecurely.evidence == (
        "(Triage Signal; source review required) App.txt: nslog; token"
    )

    no_hit = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "NSLog\nsettings"}})
    assert no_hit.sensitive_data_logged_insecurely.present is None
    assert no_hit.sensitive_data_logged_insecurely.evidence == "source_data_flow_analysis_required"


def test_ios_data_storage_evidence_wifi_mac_logged_insecurely() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.wifi-mac-logged-insecurely",
                        "path": "Sources/NetworkInfo.swift",
                        "extra": {"lines": "logger.info(wifiMac)"},
                    }
                ]
            }
        }
    )
    assert source_detected.wifi_mac_logged_insecurely.present is True
    assert source_detected.wifi_mac_logged_insecurely.evidence == "Sources/NetworkInfo.swift: logger.info(wifiMac)"

    binary_triage = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "Logger\nBSSID"}})
    assert binary_triage.wifi_mac_logged_insecurely.present is None
    assert binary_triage.wifi_mac_logged_insecurely.evidence == (
        "(Triage Signal; source review required) App.txt: logger; bssid"
    )

    no_hit = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "Logger\nnetworkName"}})
    assert no_hit.wifi_mac_logged_insecurely.present is None
    assert no_hit.wifi_mac_logged_insecurely.evidence == "source_data_flow_analysis_required"


def test_ios_data_storage_evidence_keyboard_cache_exposure_requires_source_finding() -> None:
    source_detected = IOSDataStorageEvidence(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios.storage.keyboard-cache-exposure",
                        "path": "Sources/LoginView.swift",
                        "extra": {"lines": "passwordField.autocorrectionType = .yes"},
                    }
                ]
            }
        }
    )
    assert source_detected.keyboard_cache_exposure.present is True
    assert (
        source_detected.keyboard_cache_exposure.evidence
        == "Sources/LoginView.swift: passwordField.autocorrectionType = .yes"
    )

    source_no_hit = IOSDataStorageEvidence({"opengrep": {"results": []}})
    assert source_no_hit.keyboard_cache_exposure.present is False
    assert source_no_hit.keyboard_cache_exposure.evidence == "no_keyboard_cache_exposure_hits"

    binary_only = IOSDataStorageEvidence({"strings_outputs": {"App.txt": "UITextField\nautocorrectionType"}})
    assert binary_only.keyboard_cache_exposure.present is None
    assert binary_only.keyboard_cache_exposure.evidence == "source_input_configuration_analysis_required"
