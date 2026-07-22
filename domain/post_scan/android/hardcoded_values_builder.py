"""Build hardcoded URLs, emails, and secret evidence."""

import re
from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import build_hardcoded_values


@dataclass
class HardcodedValuesBuilder:
    urls: list[dict[str, str]]
    emails: list[str]
    secrets: list[dict[str, str]]

    ENCODED_SECRET_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
    JVM_DESCRIPTOR_PATTERN = re.compile(r"^\+?L(?:[A-Za-z0-9_$]+/)+[A-Za-z0-9_$]+$")
    SECRET_LABEL_PATTERN = re.compile(
        r"(?i)^(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|secretkey)$"
    )

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        values = build_hardcoded_values(self, loaded_outputs)
        self.urls, self.emails, self.secrets = values["urls"], values["emails"], values["secrets"]

    @staticmethod
    def _first_non_empty(*values: object) -> str:
        for value in values:
            text = str(value or "").strip()
            if text:
                return text
        return ""

    @staticmethod
    def _looks_like_email(value: str) -> bool:
        local_part, _, domain_part = value.partition("@")
        return bool(local_part and "." in domain_part)

    def _looks_like_secret_label(self, value: str) -> bool:
        return self.SECRET_LABEL_PATTERN.fullmatch(value.strip()) is not None

    def _looks_like_encoded_secret(self, value: str) -> bool:
        return (
            len(value) >= 40
            and len(value) % 4 in {0, 2, 3}
            and not self.JVM_DESCRIPTOR_PATTERN.fullmatch(value)
            and any(char in value for char in "+=")
            and len(set(value)) >= 10
        )

    @staticmethod
    def _format_provenance_location(provenance: dict[str, Any]) -> str:
        path, line = str(provenance.get("path", "")).strip(), provenance.get("line")
        return f"{path}:{line}" if path and line not in (None, "") else path
