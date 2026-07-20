from typing import Any


def first_non_empty(*values: object) -> str:
    for value in values:
        if value is not None:
            text = str(value).strip()
            if text:
                return text
    return ""


def matching_api_call_sites(
    self,
    api_calls: list[dict[str, Any]],
    predicate: Any,
) -> list[str]:
    callers: list[str] = []
    for item in api_calls:
        if not isinstance(item, dict) or not predicate(item):
            continue
        caller = item.get("caller") or {}
        signature = self._first_non_empty(caller.get("signature"))
        if signature:
            callers.append(signature)
    return self._dedupe_preserve_order(callers)


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
