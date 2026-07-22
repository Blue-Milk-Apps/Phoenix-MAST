from dataclasses import dataclass, field
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class AppCertificateBuilder:
    owner_name: str = ""
    organization: str = ""
    organizational_unit: str = ""
    location: str = ""
    validity: str = ""
    issuer: str = ""
    serial_number: str = ""
    signature_versions: dict[str, bool] = field(default_factory=dict)
    hash_algorithms: str = ""
    fingerprint: str = ""
    unique_certs: str = ""

    def __init__(self, loaded_outputs):
        androguard_certificates = loaded_outputs.get("androguard_certificates") or {}

        apksigner_signing_evidence = loaded_outputs.get("apksigner_signing_evidence") or {}

        primary_certificate = self._primary_certificate(androguard_certificates, apksigner_signing_evidence)
        subject = primary_certificate.get("subject") or {}
        issuer = primary_certificate.get("issuer") or {}
        signature_schemes = apksigner_signing_evidence.get("signature_schemes") or {}
        self.owner_name = first_non_empty(
            subject.get("common_name"),
            self._extract_dn_value(
                (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get("subject_dn"),
                "CN",
            ),
        )
        self.organization = first_non_empty(
            subject.get("organization_name"),
            self._extract_dn_value(
                (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get("subject_dn"),
                "O",
            ),
        )
        self.organizational_unit = first_non_empty(
            subject.get("organizational_unit_name"),
            self._extract_dn_value(
                (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get("subject_dn"),
                "OU",
            ),
        )
        self.location = ""
        self.validity = self._format_validity(
            primary_certificate.get("not_valid_before"),
            primary_certificate.get("not_valid_after"),
        )
        self.issuer = self._format_identity(issuer)
        self.serial_number = first_non_empty(primary_certificate.get("serial_number"))
        self.signature_versions = {
            "v1": self.signature_scheme_verified(signature_schemes.get("v1")),
            "v2": self.signature_scheme_verified(signature_schemes.get("v2")),
            "v3": self.signature_scheme_verified(signature_schemes.get("v3")),
            "v4": self.signature_scheme_verified(signature_schemes.get("v4")),
        }
        self.hash_algorithms = self._format_hash_algorithms(primary_certificate, apksigner_signing_evidence)
        self.fingerprint = first_non_empty(
            primary_certificate.get("sha256"),
            (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get("sha256"),
            primary_certificate.get("sha1"),
        )
        self.unique_certs = str(len(androguard_certificates.get("all") or []))

    @staticmethod
    def signature_scheme_verified(signature_scheme: dict[str, Any] | None) -> bool:
        if not signature_scheme:
            return False
        return str(signature_scheme.get("state", "")).upper() == "VERIFIED"

    @staticmethod
    def _primary_certificate(
        androguard_certificates: dict[str, Any], apksigner_signing_evidence: dict[str, Any]
    ) -> dict[str, Any]:
        certificates = androguard_certificates.get("all") or []
        if certificates:
            return certificates[0]
        signers = apksigner_signing_evidence.get("signers") or []
        return (signers[0].get("certificate") or {}) if signers else {}

    @staticmethod
    def _extract_dn_value(distinguished_name: object, key: str) -> str:
        for part in str(distinguished_name or "").split(","):
            part = part.strip()
            if part.startswith(f"{key}="):
                return part[len(key) + 1 :].strip()
        return ""

    @staticmethod
    def _format_validity(not_before: object, not_after: object) -> str:
        start, end = str(not_before or "").strip(), str(not_after or "").strip()
        return f"{start} to {end}" if start and end else start or end

    @staticmethod
    def _format_identity(identity: dict[str, Any]) -> str:
        return ", ".join(
            value
            for value in (
                str(identity.get("common_name", "")).strip(),
                str(identity.get("organization_name", "")).strip(),
                str(identity.get("organizational_unit_name", "")).strip(),
            )
            if value
        )

    @staticmethod
    def _format_hash_algorithms(primary_certificate: dict[str, Any], apksigner_signing_evidence: dict[str, Any]) -> str:
        values = [
            "SHA1" if primary_certificate.get("sha1") else "",
            "SHA256" if primary_certificate.get("sha256") else "",
        ]
        signer = ((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}
        values.extend(
            (str(signer.get("signature_algorithm", "")).strip(), str(signer.get("public_key_algorithm", "")).strip())
        )
        return ", ".join(dict.fromkeys(value for value in values if value and value.upper() != "UNKNOWN"))
