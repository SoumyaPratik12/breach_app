from typing import Protocol

from app.schemas.scan import (
    ExposureFinding,
    FindingCategory,
    FindingSeverity,
)


class ScanProviderError(Exception):
    """Expected provider failure that can be recorded on a scan."""


class ScanProvider(Protocol):
    def scan(self) -> list[ExposureFinding]:
        """Return findings without receiving or revealing identifier values."""


class SimulatedScanProvider:
    def scan(self) -> list[ExposureFinding]:
        return [
            ExposureFinding(
                category=FindingCategory.CREDENTIAL_EXPOSURE,
                severity=FindingSeverity.HIGH,
                description=(
                    "Simulated example: a credential-related record "
                    "appeared in a mock dataset."
                ),
                source="Simulated sample dataset",
            ),
            ExposureFinding(
                category=FindingCategory.PUBLIC_PROFILE,
                severity=FindingSeverity.LOW,
                description=(
                    "Simulated example: a public profile matched a mock "
                    "record."
                ),
                source="Simulated public-profile index",
            ),
        ]


simulated_scan_provider = SimulatedScanProvider()
