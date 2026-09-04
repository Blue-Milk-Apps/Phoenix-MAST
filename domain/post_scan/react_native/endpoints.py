"""Build normalized endpoint inventory from React Native OpenGrep findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

from domain.post_scan.react_native.rule_registry import ENDPOINT_INVENTORY_RULE_ID_TO_KEY
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativeEndpoints:
    items: list[dict[str, str]]
    urls: list[dict[str, str]]
    assessed: bool

    URL_PATTERN = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\"'`\s<>()]+")
    ENVIRONMENT_PATTERN = re.compile(r"(?:process\.env|Config)\.[A-Z][A-Z0-9_]*(?:URL|URI|HOST|ENDPOINT|BASE_URL)\b")
    BASE_URL_PATTERN = re.compile(r"\bbaseURL\s*:\s*([A-Za-z_$][A-Za-z0-9_$.]*)")
    SENSITIVE_QUERY_PATTERN = re.compile(
        r"(?i)([?&](?:api[_-]?key|auth(?:orization)?|credential|pass(?:word|code|wd)?|secret|session|token)=)([^&#\s]+)"
    )
    LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "10.0.2.2", "::1"})

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        inventory_rule_ids = frozenset(ENDPOINT_INVENTORY_RULE_ID_TO_KEY)
        self.assessed = context.opengrep_scope_assessed("react_native", inventory_rule_ids)
        candidates: list[dict[str, str]] = []
        for finding in context.opengrep_results_for_scope("react_native"):
            rule_id = context.first_non_empty(finding.get("check_id"))
            inventory_key = ENDPOINT_INVENTORY_RULE_ID_TO_KEY.get(rule_id)
            if inventory_key is None:
                continue
            candidates.extend(self._finding_candidates(context, finding, inventory_key))

        self.items = self._deduplicate(candidates)
        self.urls = [
            {
                "url": item["endpoint"],
                "country": "",
                "location": item["source"],
            }
            for item in self.items
            if item["confidence"] == "literal"
        ]

    @classmethod
    def _finding_candidates(
        cls,
        context: ReactNativeScanExtractionContext,
        finding: dict[str, object],
        inventory_key: str,
    ) -> list[dict[str, str]]:
        extra = context.mapping(finding.get("extra"))
        text = context.first_non_empty(extra.get("lines"), extra.get("message"))
        source = cls._location(context, finding)
        if inventory_key == "url_literal":
            return [cls._literal_item(value, text, source) for value in cls.URL_PATTERN.findall(text)]
        if inventory_key == "environment_reference":
            return [cls._dynamic_item(value, "environment", source) for value in cls.ENVIRONMENT_PATTERN.findall(text)]
        if inventory_key == "base_url_reference":
            return [cls._dynamic_item(value, "base-url", source) for value in cls.BASE_URL_PATTERN.findall(text)]
        return []

    @classmethod
    def _literal_item(cls, value: str, context_line: str, source: str) -> dict[str, str]:
        value = value.rstrip(".,;")
        parsed = urlsplit(value)
        endpoint = cls._normalize_and_redact(value, parsed)
        scheme = parsed.scheme.casefold()
        hostname = (parsed.hostname or "").casefold()
        connection = cls._connection_type(scheme, context_line)
        security = (
            "local" if hostname in cls.LOCAL_HOSTS else "encrypted" if scheme in {"https", "wss"} else "cleartext"
        )
        tags = [connection, security]
        if "${" in endpoint:
            tags.append("dynamic-template")
        return {
            "endpoint": endpoint,
            "tags": ", ".join(tags),
            "ip_address": "",
            "country": "",
            "source": source,
            "connection_type": connection,
            "transport_security": security,
            "confidence": "literal",
        }

    @staticmethod
    def _dynamic_item(value: str, kind: str, source: str) -> dict[str, str]:
        return {
            "endpoint": value,
            "tags": f"dynamic, {kind}",
            "ip_address": "",
            "country": "",
            "source": source,
            "connection_type": kind,
            "transport_security": "unknown",
            "confidence": "dynamic",
        }

    @classmethod
    def _normalize_and_redact(cls, value: str, parsed: SplitResult) -> str:
        scheme = str(parsed.scheme).casefold()
        hostname = str(parsed.hostname or "").casefold()
        if not hostname:
            return cls.SENSITIVE_QUERY_PATTERN.sub(r"\1[REDACTED]", value)
        rendered_host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        port_suffix = f":{port}" if port is not None and not default_port else ""
        userinfo = "[REDACTED]@" if parsed.username is not None else ""
        normalized = urlunsplit(
            (
                scheme,
                f"{userinfo}{rendered_host}{port_suffix}",
                parsed.path,
                parsed.query,
                "",
            )
        )
        return cls.SENSITIVE_QUERY_PATTERN.sub(r"\1[REDACTED]", normalized)

    @staticmethod
    def _connection_type(scheme: str, context_line: str) -> str:
        lowered = context_line.casefold()
        if "webview" in lowered:
            return "webview"
        if "websocket" in lowered or scheme in {"ws", "wss"}:
            return "websocket"
        if "axios" in lowered:
            return "axios"
        if "fetch" in lowered:
            return "fetch"
        if scheme == "ftp":
            return "ftp"
        return "http"

    @staticmethod
    def _location(context: ReactNativeScanExtractionContext, finding: dict[str, object]) -> str:
        text = context.first_non_empty(finding.get("path"))
        if text:
            path = Path(text)
            if path.is_absolute():
                try:
                    text = path.relative_to(context.project_path).as_posix()
                except ValueError:
                    text = path.as_posix()
        start = context.mapping(finding.get("start"))
        line = start.get("line")
        return f"{text}:{line}" if text and line not in (None, "") else text

    @staticmethod
    def _deduplicate(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
        grouped: dict[str, dict[str, str]] = {}
        locations: dict[str, list[str]] = {}
        tags: dict[str, list[str]] = {}
        for item in candidates:
            endpoint = item["endpoint"]
            if not endpoint:
                continue
            if endpoint not in grouped:
                grouped[endpoint] = dict(item)
                locations[endpoint] = []
                tags[endpoint] = []
            if item["source"] and item["source"] not in locations[endpoint]:
                locations[endpoint].append(item["source"])
            for tag in (part.strip() for part in item["tags"].split(",")):
                if tag and tag not in tags[endpoint]:
                    tags[endpoint].append(tag)
        for endpoint, item in grouped.items():
            item["source"] = ", ".join(locations[endpoint][:5])
            item["tags"] = ", ".join(tags[endpoint])
        return list(grouped.values())
