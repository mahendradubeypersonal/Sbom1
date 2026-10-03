"""Acceptance oracles used by the descent loop (ADR-19)."""

from __future__ import annotations

from typing import Any, Protocol

from .jsonutil import sha256_of
from .profile import Profile


class Oracle(Protocol):
    def accepts(self, doc: Any, spec: str, version: str) -> tuple[bool, str]: ...


class AcceptanceClient(Protocol):
    """Anything that can try a document against the real consumer (implemented by the Checkmarx client)."""

    def check(self, doc: Any, spec: str, version: str) -> tuple[bool, str]: ...


class ProfileOracle:
    """Offline default: a version is accepted when it is in the profile's accepted_versions."""

    def __init__(self, profile: Profile) -> None:
        self.profile = profile

    def accepts(self, doc: Any, spec: str, version: str) -> tuple[bool, str]:
        accepted = self.profile.rules_for(spec).accepted_versions
        if version in accepted:
            return True, f"schema-valid and {version} is in accepted_versions"
        return False, f"schema-valid, but {version} is not in accepted_versions ({', '.join(accepted)})"


class SchemaOnlyOracle:
    """Any schema-valid version is OK."""

    def accepts(self, doc: Any, spec: str, version: str) -> tuple[bool, str]:
        return True, "schema-valid"


class CheckmarxOracle:
    """Real test upload per level. Results are cached by (document hash, version); uploads are budgeted."""

    def __init__(self, client: AcceptanceClient, max_uploads: int = 6) -> None:
        self.client = client
        self.max_uploads = max_uploads
        self.uploads = 0
        self.cache: dict[tuple[str, str], tuple[bool, str]] = {}

    def accepts(self, doc: Any, spec: str, version: str) -> tuple[bool, str]:
        key = (sha256_of(doc), version)
        if key in self.cache:
            ok, reason = self.cache[key]
            return ok, reason + " (cached)"
        if self.uploads >= self.max_uploads:
            return False, f"upload budget of {self.max_uploads} used up; {version} not tried"
        self.uploads += 1
        ok, reason = self.client.check(doc, spec, version)
        self.cache[key] = (ok, reason)
        return ok, reason


def oracle_for(profile: Profile, mode: str | None = None, client: AcceptanceClient | None = None,
               max_uploads: int = 6) -> Oracle:
    mode = mode or profile.acceptance
    if mode == "schema-only":
        return SchemaOnlyOracle()
    if mode == "checkmarx":
        if client is None:
            raise ValueError("acceptance 'checkmarx' needs a Checkmarx client (see sbom-fixer verify --help)")
        return CheckmarxOracle(client, max_uploads)
    return ProfileOracle(profile)
