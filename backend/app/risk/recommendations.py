"""Deterministic, advisory remediation recommendations."""

from app.schemas.scan import ExposureFinding, FindingCategory, FindingSeverity


def recommend_for_finding(finding: ExposureFinding) -> dict:
    """Return actionable guidance without claiming an exposure is verified."""

    if finding.category == FindingCategory.CREDENTIAL_EXPOSURE:
        if finding.severity == FindingSeverity.HIGH:
            priority = "high"
            title = "Review credential security"
            steps = [
                "If independently confirmed, change the affected credential.",
                "Revoke and replace any confirmed exposed access tokens or keys.",
                "Enable multi-factor authentication where available.",
                "Check for credential reuse and update other affected accounts.",
            ]
        else:
            priority = (
                "medium"
                if finding.severity == FindingSeverity.MEDIUM
                else "low"
            )
            title = "Check account credentials"
            steps = [
                "Verify the reported concern using a trusted source.",
                "Change the affected credential if exposure is confirmed.",
                "Avoid reusing passwords and enable multi-factor authentication.",
            ]

    elif finding.category == FindingCategory.PUBLIC_PROFILE:
        priority = (
            "medium"
            if finding.severity == FindingSeverity.HIGH
            else "low"
            if finding.severity == FindingSeverity.LOW
            else "medium"
        )
        title = "Review public profile visibility"
        steps = [
            "Review which profile details are publicly visible.",
            "Remove personal details that do not need to be public.",
            "Check privacy settings on the relevant service.",
        ]

    else:
        # Defensive fallback if new categories are introduced later.
        priority = "medium"
        title = "Review this finding"
        steps = [
            "Verify the finding with a trusted source before taking action.",
            "Follow the relevant service's official security guidance.",
        ]

    return {
        "category": finding.category.value,
        "severity": finding.severity.value,
        "priority": priority,
        "title": title,
        "steps": steps,
        "simulated": finding.simulated,
        "verified": finding.verified,
        "advisory_only": True,
    }


def recommend_for_findings(
    findings: list[ExposureFinding],
) -> list[dict]:
    """Return recommendations in the same order as the supplied findings."""
    return [recommend_for_finding(finding) for finding in findings]