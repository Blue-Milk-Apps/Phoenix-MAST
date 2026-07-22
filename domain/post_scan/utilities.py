from typing import Any, Callable


def first_non_empty(*values: object) -> str:
    for value in values:
        if value is not None:
            text = str(value).strip()
            if text:
                return text
    return ""


def coerce_bool_like(value: object) -> bool | None:
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def app_package_prefix(loaded_outputs: dict[str, Any]) -> str:
    return first_non_empty(
        (loaded_outputs.get("aapt2_identity") or {}).get("package_name"),
        (loaded_outputs.get("androguard_metadata") or {}).get("package"),
    ).replace(".", "/")


def api_call_signature(item: dict[str, Any]) -> str:
    callee = item.get("callee") or {}
    return first_non_empty(callee.get("signature"), callee.get("class_name"), callee.get("method_name"))


def api_call_caller_signature(item: dict[str, Any]) -> str:
    caller = item.get("caller") or {}
    return first_non_empty(caller.get("signature"), caller.get("class_name"), caller.get("method_name"))


def caller_matches_package(item: dict[str, Any], package_prefix: str) -> bool:
    return bool(package_prefix and package_prefix in api_call_caller_signature(item).replace(".", "/"))


def dedupe_preserve_order(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def matching_api_call_sites(api_calls: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]) -> list[str]:
    return dedupe_preserve_order(
        [api_call_caller_signature(item) for item in api_calls if isinstance(item, dict) and predicate(item)]
    )


def matching_string_xrefs(
    loaded_outputs: dict[str, Any],
    value_predicate: Callable[[str], bool],
    xref_predicate: Callable[[str], bool],
) -> list[str]:
    matches: list[str] = []
    for item in (loaded_outputs.get("androguard_strings") or {}).get("items") or []:
        if not isinstance(item, dict) or not value_predicate(first_non_empty(item.get("value"))):
            continue
        for xref in item.get("xrefs") or []:
            if isinstance(xref, dict):
                signature = first_non_empty(xref.get("signature"))
                if signature and xref_predicate(signature):
                    matches.append(signature)
    return dedupe_preserve_order(matches)


def build_hardcoded_values(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
    apktool_secrets_endpoints = loaded_outputs.get("apktool_secrets_endpoints") or {}
    strings_outputs = loaded_outputs.get("strings_outputs") or {}

    urls: list[dict[str, str]] = []
    emails: list[str] = []
    secrets: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    seen_emails: set[str] = set()
    seen_secrets: set[tuple[str, str]] = set()

    for item in apktool_secrets_endpoints.get("items") or []:
        context = item.get("context") or {}
        category = str(context.get("category", "")).strip().lower()
        value = self._first_non_empty(item.get("value"))
        if not value:
            continue

        if category == "url":
            if value in seen_urls:
                continue
            seen_urls.add(value)
            urls.append({"url": value, "country": ""})
            continue

        if self._looks_like_email(value):
            if value in seen_emails:
                continue
            seen_emails.add(value)
            emails.append(value)
            continue

        if category == "secret_keyword":
            if self._looks_like_secret_label(value):
                continue
            location = self._format_provenance_location(item.get("provenance") or {})
            dedupe_key = (value, location)
            if dedupe_key in seen_secrets:
                continue
            seen_secrets.add(dedupe_key)
            secrets.append({"value": value, "location": location})

    for source_name, content in strings_outputs.items():
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in self.ENCODED_SECRET_PATTERN.finditer(line):
                value = match.group(0)
                if not self._looks_like_encoded_secret(value):
                    continue
                location = f"strings/{source_name}:{line_number}"
                dedupe_key = (value, location)
                if dedupe_key in seen_secrets:
                    continue
                seen_secrets.add(dedupe_key)
                secrets.append({"value": value, "location": location})

    return {
        "urls": urls,
        "emails": emails,
        "secrets": secrets,
    }
