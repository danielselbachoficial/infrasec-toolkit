from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, select_autoescape

from infrasec_audit.models import FindingsReport
from infrasec_audit.utils.redact import redact_mapping

_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>InfraSec Audit Report</title>
  <style>
    body {
      font-family: "Inter", "Segoe UI", Arial, sans-serif;
      background: #f5f7fb;
      color: #1f2937;
      margin: 0;
    }
    header { background: #0f172a; color: #fff; padding: 40px; }
    header h1 { margin: 0 0 8px 0; font-size: 32px; }
    header p { margin: 0; opacity: 0.8; }
    .container { padding: 32px; }
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
    }
    .card {
      background: #fff;
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
    }
    .critical { background: #fee2e2; color: #991b1b; }
    .high { background: #ffedd5; color: #9a3412; }
    .medium { background: #fef9c3; color: #92400e; }
    .low { background: #dcfce7; color: #166534; }
    .table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    .table th, .table td { padding: 12px; border-bottom: 1px solid #e5e7eb; text-align: left; }
    .section { margin-top: 32px; }
    .finding {
      background: #fff;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 16px;
      box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
    }
    .muted { color: #6b7280; font-size: 14px; }
  </style>
</head>
<body>
  <header>
    <h1>InfraSec Audit Report</h1>
    <p>Cliente/ambiente: <strong>{{ client_name }}</strong> | Gerado em {{ generated_at }}</p>
  </header>
  <div class="container">
    <section class="cards">
      <div class="card">
        <h3>Score de Risco</h3>
        <p style="font-size: 28px; margin: 8px 0;">{{ risk_score }}</p>
        <p class="muted">0 (baixo) - 100 (alto)</p>
      </div>
      <div class="card">
        <h3>Crítico</h3>
        <span class="badge critical">{{ counts.critical }}</span>
      </div>
      <div class="card">
        <h3>Alto</h3>
        <span class="badge high">{{ counts.high }}</span>
      </div>
      <div class="card">
        <h3>Médio</h3>
        <span class="badge medium">{{ counts.medium }}</span>
      </div>
      <div class="card">
        <h3>Baixo</h3>
        <span class="badge low">{{ counts.low }}</span>
      </div>
    </section>

    <section class="section">
      <h2>Sumário Executivo</h2>
      <p>
        Host analisado: <strong>{{ system.hostname }}</strong>
        ({{ system.os_name }} {{ system.os_version or "" }})
      </p>
      <p>Kernel: {{ system.kernel }}</p>
      <p class="muted">
        Este relatório consolida evidências fornecidas e inventário local,
        correlacionando CVEs com base em fontes públicas.
      </p>
    </section>

    <section class="section">
      <h2>Visão por Severidade</h2>
      <table class="table">
        <thead>
          <tr><th>Severidade</th><th>Quantidade</th></tr>
        </thead>
        <tbody>
          <tr><td>Crítico</td><td>{{ counts.critical }}</td></tr>
          <tr><td>Alto</td><td>{{ counts.high }}</td></tr>
          <tr><td>Médio</td><td>{{ counts.medium }}</td></tr>
          <tr><td>Baixo</td><td>{{ counts.low }}</td></tr>
        </tbody>
      </table>
    </section>

    <section class="section">
      <h2>Achados</h2>
      {% for finding in findings %}
        <div class="finding">
          <h3>{{ finding.cve }} - {{ finding.component }}</h3>
          <p class="muted">
            Versão detectada: {{ finding.version or "N/A" }} |
            Severidade: {{ finding.severity or "N/A" }}
          </p>
          <p>{{ finding.summary or "Sem resumo disponível." }}</p>
          {% if finding.evidence %}
            <p><strong>Evidências:</strong> {{ finding.evidence | join(", ") }}</p>
          {% endif %}
          {% if finding.references %}
            <p><strong>Referências:</strong> {{ finding.references | join(", ") }}</p>
          {% endif %}
          {% if finding.recommendations %}
            <p><strong>Recomendações defensivas:</strong></p>
            <ul>
              {% for rec in finding.recommendations %}
                <li><strong>{{ rec.title }}:</strong> {{ rec.details }}</li>
              {% endfor %}
            </ul>
          {% endif %}
        </div>
      {% endfor %}
    </section>

    <section class="section">
      <h2>Observações e Limitações</h2>
      <ul>
        {% for note in notes %}
          <li>{{ note }}</li>
        {% endfor %}
      </ul>
    </section>
  </div>
</body>
</html>
"""


def render_html(report: FindingsReport, redact: bool, client_name: str | None) -> str:
    data = report.model_dump(mode="json")
    if redact:
        data = redact_mapping(data)
    env = Environment(autoescape=select_autoescape())
    template = env.from_string(_TEMPLATE)
    return template.render(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        client_name=client_name or "[preencher]",
        **data,
    )


def write_html(
    report: FindingsReport,
    output_path: Path,
    redact: bool,
    client_name: str | None,
) -> None:
    html = render_html(report, redact=redact, client_name=client_name)
    output_path.write_text(html, encoding="utf-8")
