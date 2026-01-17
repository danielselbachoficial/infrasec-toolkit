from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from infrasec_audit.collectors.local import (
    artifacts_to_json,
    collect_local_artifacts,
    load_artifacts,
)
from infrasec_audit.cve.osv import OsvClient, default_cache
from infrasec_audit.models import Evidence, EvidenceItem, Finding, FindingsReport, Recommendation
from infrasec_audit.parsers import parse_grype, parse_nmap_xml, parse_osv, parse_trivy
from infrasec_audit.reporting.html_report import write_html
from infrasec_audit.reporting.pdf_report import write_pdf
from infrasec_audit.utils.cache import default_cache_dir

app = typer.Typer(add_completion=False)
console = Console()
logger = logging.getLogger("infrasec-audit")

COLLECT_MODE = typer.Option("local", help="Modo de coleta (apenas local no MVP).")
COLLECT_OUT = typer.Option(Path("artifacts.json"), help="Arquivo de saída JSON.")
COLLECT_AUTH = typer.Option(
    False,
    "--i-have-authorization",
    help="Confirma autorização explícita para coleta além de leitura local.",
)
COLLECT_VERBOSE = typer.Option(False, help="Logs detalhados.")

INGEST_INPUT = typer.Option(..., help="Arquivo de evidências (JSON/XML).")
INGEST_TYPE = typer.Option(
    ...,
    help="Tipo do scanner: trivy|grype|osv|nmap-xml|generic-json",
)
INGEST_OUT = typer.Option(Path("evidence.json"), help="Arquivo de saída JSON.")
INGEST_VERBOSE = typer.Option(False, help="Logs detalhados.")

ANALYZE_ARTIFACTS = typer.Option(..., help="Arquivo artifacts.json.")
ANALYZE_EVIDENCE = typer.Option(None, help="Arquivo evidence.json.")
ANALYZE_OUT = typer.Option(Path("findings.json"), help="Arquivo de saída JSON.")
ANALYZE_CACHE_TTL = typer.Option(86400, help="TTL do cache em segundos.")
ANALYZE_OFFLINE = typer.Option(False, help="Não realizar consultas externas.")
ANALYZE_VERBOSE = typer.Option(False, help="Logs detalhados.")

REPORT_FINDINGS = typer.Option(..., help="Arquivo findings.json.")
REPORT_FORMAT = typer.Option("html,pdf", help="Formatos: html,pdf")
REPORT_OUT_DIR = typer.Option(Path("report"), help="Diretório de saída.")
REPORT_REDACT = typer.Option(False, help="Mascarar IPs/hostnames.")
REPORT_CLIENT = typer.Option(None, help="Nome do cliente/ambiente.")
REPORT_VERBOSE = typer.Option(False, help="Logs detalhados.")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")


@app.command()
def collect(
    mode: str = COLLECT_MODE,
    out: Path = COLLECT_OUT,
    i_have_authorization: bool = COLLECT_AUTH,
    verbose: bool = COLLECT_VERBOSE,
) -> None:
    """Coleta inventário local do host."""
    _setup_logging(verbose)
    if mode != "local":
        raise typer.BadParameter("Apenas modo local é suportado no MVP.")
    if not i_have_authorization:
        raise typer.BadParameter("Você deve confirmar --i-have-authorization para coleta.")

    artifacts = collect_local_artifacts()
    artifacts_to_json(artifacts, out)
    console.print(f"✅ Coleta concluída: {out}")


@app.command()
def ingest(
    input: Path = INGEST_INPUT,
    type: str = INGEST_TYPE,
    out: Path = INGEST_OUT,
    verbose: bool = INGEST_VERBOSE,
) -> None:
    """Normaliza evidências de scanners externos."""
    _setup_logging(verbose)
    raw = input.read_text(encoding="utf-8")
    items: list[EvidenceItem] = []

    if type == "trivy":
        items = parse_trivy(json.loads(raw))
    elif type == "grype":
        items = parse_grype(json.loads(raw))
    elif type == "osv":
        items = parse_osv(json.loads(raw))
    elif type == "nmap-xml":
        items = parse_nmap_xml(raw)
    elif type == "generic-json":
        data = json.loads(raw)
        for entry in data.get("items", []):
            items.append(EvidenceItem.model_validate(entry))
    else:
        raise typer.BadParameter("Tipo de evidência não suportado.")

    evidence = Evidence(items=items)
    out.write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"✅ Evidência normalizada: {out}")


@app.command()
def analyze(
    artifacts: Path = ANALYZE_ARTIFACTS,
    evidence: Path | None = ANALYZE_EVIDENCE,
    out: Path = ANALYZE_OUT,
    cache_ttl: int = ANALYZE_CACHE_TTL,
    offline: bool = ANALYZE_OFFLINE,
    verbose: bool = ANALYZE_VERBOSE,
) -> None:
    """Correlaciona inventário com CVEs e gera achados."""
    _setup_logging(verbose)
    artifacts_data = load_artifacts(artifacts)
    evidence_data = None
    if evidence and evidence.exists():
        evidence_data = Evidence.model_validate_json(evidence.read_text(encoding="utf-8"))

    findings: list[Finding] = []
    cache = default_cache(cache_ttl)
    client = OsvClient(cache)

    components = {(pkg.name, pkg.version, pkg.manager) for pkg in artifacts_data.packages}

    for name, version, manager in components:
        ecosystem = {
            "dpkg": "Debian",
            "rpm": "Red Hat",
            "pacman": "Arch",
        }.get(manager)
        response = (
            client.cached_lookup(name, version, ecosystem)
            if offline
            else client.query(name, version, ecosystem)
        )
        for vuln in response.get("vulns", []) or []:
            summary = vuln.get("summary") or vuln.get("details")
            severity = None
            severity_data = vuln.get("severity") or []
            if severity_data:
                severity = severity_data[0].get("type")
            cve = vuln.get("id", "unknown")
            findings.append(
                Finding(
                    cve=cve,
                    component=name,
                    version=version,
                    severity=severity,
                    summary=summary,
                    references=[
                        ref.get("url")
                        for ref in vuln.get("references", [])
                        if ref.get("url")
                    ],
                    evidence=["osv"],
                    recommendations=_recommendations(severity),
                )
            )

    if evidence_data:
        for item in evidence_data.items:
            findings.append(
                Finding(
                    cve=item.identifier,
                    component=item.component or "unknown",
                    version=item.version,
                    severity=item.severity,
                    summary=item.summary,
                    references=[item.reference] if item.reference else [],
                    evidence=[item.source],
                    recommendations=_recommendations(item.severity),
                )
            )

    counts = _severity_counts(findings)
    report = FindingsReport(
        system=artifacts_data.system,
        findings=findings,
        counts=counts,
        risk_score=_risk_score(counts),
        notes=[
            "A coleta é baseada em evidências fornecidas e inventário local.",
            "Nenhuma exploração ou varredura ativa foi executada.",
            "Recomenda-se validar com janelas de manutenção e backups antes de aplicar correções.",
        ],
    )
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    table = Table(title="Resumo de Achados")
    table.add_column("Severidade")
    table.add_column("Quantidade")
    for sev, count in counts.items():
        table.add_row(sev, str(count))
    console.print(table)
    console.print(f"✅ Achados gerados: {out}")
    console.print(f"Cache: {default_cache_dir()}")


@app.command()
def report(
    findings: Path = REPORT_FINDINGS,
    format: str = REPORT_FORMAT,
    out_dir: Path = REPORT_OUT_DIR,
    redact: bool = REPORT_REDACT,
    client_name: str | None = REPORT_CLIENT,
    verbose: bool = REPORT_VERBOSE,
) -> None:
    """Gera relatórios HTML/PDF."""
    _setup_logging(verbose)
    report_data = FindingsReport.model_validate_json(findings.read_text(encoding="utf-8"))
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = [fmt.strip().lower() for fmt in format.split(",")]

    if "html" in formats:
        write_html(report_data, out_dir / "index.html", redact=redact, client_name=client_name)
        console.print(f"✅ HTML gerado: {out_dir / 'index.html'}")

    if "pdf" in formats:
        write_pdf(report_data, out_dir / "report.pdf", redact=redact, client_name=client_name)
        console.print(f"✅ PDF gerado: {out_dir / 'report.pdf'}")


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev = (finding.severity or "").lower()
        if sev not in counts:
            sev = "low" if sev else "low"
        counts[sev] += 1
    return counts


def _risk_score(counts: dict[str, int]) -> int:
    score = (
        counts.get("critical", 0) * 10
        + counts.get("high", 0) * 7
        + counts.get("medium", 0) * 4
        + counts.get("low", 0) * 1
    )
    return min(score, 100)


def _recommendations(severity: str | None) -> list[Recommendation]:
    base = [
        Recommendation(
            title="Atualizar componente",
            details="Aplicar patches oficiais e validar em homologação.",
        ),
        Recommendation(
            title="Monitoramento contínuo",
            details="Revisar controles de detecção e alertas para o componente afetado.",
        ),
    ]
    if severity and severity.lower() in {"critical", "high"}:
        base.append(
            Recommendation(
                title="Mitigação imediata",
                details="Isolar o serviço exposto e revisar regras de firewall temporariamente.",
            )
        )
    return base
