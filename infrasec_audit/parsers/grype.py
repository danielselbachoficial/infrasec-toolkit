from __future__ import annotations

from infrasec_audit.models import EvidenceItem


def parse_grype(data: dict) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        items.append(
            EvidenceItem(
                source="grype",
                identifier=vuln.get("id", "unknown"),
                component=artifact.get("name"),
                version=artifact.get("version"),
                severity=vuln.get("severity"),
                summary=vuln.get("description"),
                reference=(vuln.get("dataSource") or ""),
            )
        )
    return items
