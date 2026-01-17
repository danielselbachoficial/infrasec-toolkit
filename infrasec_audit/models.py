from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class SystemInfo(BaseModel):
    hostname: str
    os_name: str
    os_version: str | None = None
    kernel: str | None = None


class PackageInfo(BaseModel):
    name: str
    version: str | None = None
    manager: Literal["dpkg", "rpm", "pacman", "unknown"] = "unknown"


class ServiceInfo(BaseModel):
    name: str
    protocol: str
    local_address: str
    port: int | None = None
    process: str | None = None


class BinaryInfo(BaseModel):
    name: str
    version: str | None = None
    path: str | None = None


class Artifacts(BaseModel):
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    system: SystemInfo
    packages: list[PackageInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    binaries: list[BinaryInfo] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    source: str
    identifier: str
    component: str | None = None
    version: str | None = None
    severity: str | None = None
    summary: str | None = None
    reference: str | None = None


class Evidence(BaseModel):
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    items: list[EvidenceItem] = Field(default_factory=list)


class Recommendation(BaseModel):
    title: str
    details: str


class Finding(BaseModel):
    cve: str
    component: str
    version: str | None = None
    severity: str | None = None
    summary: str | None = None
    references: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)


class FindingsReport(BaseModel):
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    system: SystemInfo
    findings: list[Finding] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    risk_score: int = 0
    notes: list[str] = Field(default_factory=list)
