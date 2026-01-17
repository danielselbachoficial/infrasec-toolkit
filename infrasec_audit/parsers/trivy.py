from __future__ import annotations

from infrasec_audit.models import EvidenceItem


def parse_trivy(data: dict) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for result in data.get("Results", []):
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities", []) or []:
            items.append(
                EvidenceItem(
                    source=f"trivy:{target}",
                    identifier=vuln.get("VulnerabilityID", "unknown"),
                    component=vuln.get("PkgName"),
                    version=vuln.get("InstalledVersion"),
                    severity=vuln.get("Severity"),
                    summary=vuln.get("Title") or vuln.get("Description"),
                    reference=(vuln.get("PrimaryURL") or ""),
                )
            )
    return items
