from adapters.post_scan import AndroidBinaryScanDetailExtractor


def test_android_binary_scan_detail_extractor_builds_data_storage_evidence_from_permissions_and_api_calls() -> None:
    loaded_outputs = {
        "aapt2_permissions": {
            "permissions": [
                {
                    "name": "android.permission.READ_EXTERNAL_STORAGE",
                    "protection_level_hint": "dangerous",
                },
                {
                    "name": "android.permission.WRITE_EXTERNAL_STORAGE",
                    "protection_level_hint": "dangerous",
                },
            ]
        },
        "androguard_api_calls": {
            "items": [
                {
                    "callee": {
                        "method_name": "getSharedPreferences",
                        "signature": (
                            "Landroid/content/Context; getSharedPreferences "
                            "(Ljava/lang/String; I)Landroid/content/SharedPreferences;"
                        ),
                    },
                    "caller": {
                        "signature": ("Lcom/example/LoginActivity; savePassword (Ljava/lang/String;)V"),
                    },
                }
            ]
        },
        "opengrep": {"results": []},
    }

    sections = AndroidBinaryScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["data_storage_evidence"] == {
        "accesses_external_storage": {
            "present": True,
            "evidence": ("android.permission.READ_EXTERNAL_STORAGE, android.permission.WRITE_EXTERNAL_STORAGE"),
        },
        "authentication_credentials_not_protected_with_android_keystore": {
            "present": True,
            "evidence": "Lcom/example/LoginActivity; savePassword (Ljava/lang/String;)V",
        },
        "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage": {
            "present": False,
            "evidence": "no_world_readable_internal_storage_hits",
        },
        "sensitive_information_stored_in_external_storage": {
            "present": False,
            "evidence": "no_external_storage_sensitive_hits",
        },
        "does_not_prevent_screen_capture_of_sensitive_information": {
            "present": None,
            "evidence": "",
        },
    }
