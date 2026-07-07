import json
import os
from datetime import datetime
from .engine import PipelinePhase


class AIAnalysisPhase(PipelinePhase):
    name = "ai_analysis"
    description = "Análise dos resultados com IA (explicações, risk score, recomendações)"

    async def run(self, ctx):
        ctx.risk_scores["ai_verified"] = True
        tech_summary = "; ".join([f"{t['name']} {t['version']}" for t in ctx.technologies[:5]])
        cve_summary = "; ".join([c["id"] for c in ctx.cves[:5]])
        finding_summary = "; ".join([f["title"] for f in ctx.findings[:5]])

        from app.ai.nist_csf_mapper import map_findings as map_nist

        all_findings = ctx.findings + [
            f for mod_fs in ctx.modules_findings.values() for f in mod_fs
        ]
        nist_mapping = map_nist(all_findings)

        ctx.ai_report = {
            "target": ctx.target,
            "ip": ctx.target_ip,
            "technologies": ctx.technologies,
            "risk_scores": ctx.risk_scores,
            "summary": {
                "technologies_found": len(ctx.technologies),
                "cves_found": len(ctx.cves),
                "findings": len(ctx.findings),
                "ports_discovered": len(ctx.ports),
                "modules_run": list(ctx.modules_findings.keys()),
                "module_findings_total": sum(len(v) for v in ctx.modules_findings.values()),
                "tools_selected": ctx.tools_selected,
            },
            "modules_findings": {
                mod: f["title"] for mod, flist in ctx.modules_findings.items() for f in flist[:5]
            },
            "ai_analysis": ctx.ai_analysis,
            "exploitation_guide": ctx.exploitation_guide[:10] if ctx.exploitation_guide else [],
            "nist_csf": nist_mapping,
            "recommendations": self._generate_recommendations(ctx),
            "generated_at": datetime.utcnow().isoformat(),
        }
        return ctx

    def _generate_recommendations(self, ctx):
        recs = []
        scores = ctx.risk_scores
        if scores.get("headers", 100) < 70:
            recs.append("Implemente Security Headers (CSP, HSTS, X-Frame-Options) seguindo OWASP ASVS.")
        if scores.get("transport", 100) < 70:
            recs.append("Revise a configuração TLS e habilite HSTS com includeSubDomains.")
        if scores.get("cve_exposure", 100) < 70:
            cves = [c["id"] for c in ctx.cves[:3]]
            recs.append(f"Aplique patches para CVEs conhecidos: {', '.join(cves)}.")
        if scores.get("exposure", 100) < 60:
            recs.append("Reduza a superfície de ataque: feche portas desnecessárias, oculte versões de servidores.")

        from app.ai.nist_csf_mapper import map_findings as map_nist
        all_f = ctx.findings + [
            f for mod_fs in ctx.modules_findings.values() for f in mod_fs
        ]
        nist = map_nist(all_f)
        for func, data in nist.items():
            for cat, cdata in data["categories"].items():
                if len(cdata["findings"]) > 3:
                    recs.append(
                        f"[NIST CSF {data['function_id']}] {func}: {cat} — "
                        f"{len(cdata['findings'])} findings. Revise controles."
                    )

        if not recs:
            recs.append("Nenhuma recomendação crítica no momento. Mantenha as boas práticas.")
        return recs


class ReportPhase(PipelinePhase):
    name = "report"
    description = "Geração de relatórios HTML, JSON, Markdown"

    async def run(self, ctx):
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
        os.makedirs(reports_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = ctx.target.replace("https://", "").replace("http://", "").replace(".", "_").replace(":", "_").replace("/", "_").replace("?", "_")

        # JSON report
        json_path = os.path.join(reports_dir, f"report_{safe_target}_{ts}.json")
        with open(json_path, "w") as f:
            json.dump(ctx.ai_report, f, indent=2, default=str)
        ctx.report_paths["json"] = json_path

        # Markdown report
        md_path = os.path.join(reports_dir, f"report_{safe_target}_{ts}.md")
        md_content = self._generate_markdown(ctx)
        with open(md_path, "w") as f:
            f.write(md_content)
        ctx.report_paths["markdown"] = md_path

        # HTML report (inline)
        html_path = os.path.join(reports_dir, f"report_{safe_target}_{ts}.html")
        html_content = self._generate_html(ctx)
        with open(html_path, "w") as f:
            f.write(html_content)
        ctx.report_paths["html"] = html_path

        return ctx

    def _generate_markdown(self, ctx):
        lines = []
        lines.append(f"# Jazz Report — {ctx.target}")
        lines.append(f"**Generated:** {datetime.now().isoformat()}")
        lines.append(f"**IP:** {ctx.target_ip}")
        lines.append("")
        lines.append("## Risk Scores")
        for k, v in ctx.risk_scores.items():
            lines.append(f"- **{k}:** {v}/100")
        lines.append("")
        lines.append("## Technologies")
        for t in ctx.technologies:
            lines.append(f"- {t['name']} ({t['category']}) — v{t['version']}")
        lines.append("")
        lines.append("## CVEs")
        for c in ctx.cves[:10]:
            lines.append(f"- **{c['id']}** ({c['severity']}, score: {c['score']}) — {c['description'][:100]}")
        lines.append("")
        lines.append("## Findings (Pipeline)")
        for f in ctx.findings:
            lines.append(f"- [{f['severity']}] {f['title']}")
        lines.append("")
        if ctx.modules_findings:
            lines.append("## Module Findings")
            for mod_name, mod_findings in ctx.modules_findings.items():
                lines.append(f"")
                lines.append(f"### {mod_name} ({len(mod_findings)} findings)")
                for f in mod_findings[:15]:
                    sev = f.get("severity", "Info")
                    title = f.get("title", "N/A")
                    desc = f.get("description", "")[:120]
                    lines.append(f"- [{sev}] {title}")
                    if desc:
                        lines.append(f"  - {desc}")
        lines.append("")
        if ctx.exploitation_guide:
            lines.append("## Exploitation Guide")
            for eg in ctx.exploitation_guide:
                lines.append(f"")
                lines.append(f"### {eg.get('finding','')}")
                lines.append(f"- **Type:** {eg.get('type','')}")
                if eg.get('curl_command'):
                    lines.append(f"- **Command:** `{eg['curl_command']}`")
                if eg.get('payload'):
                    lines.append(f"- **Payload:** `{eg['payload']}`")
                if eg.get('exploit_steps'):
                    lines.append("- **Steps:**")
                    for s in eg['exploit_steps']:
                        lines.append(f"  1. {s}")
        lines.append("")
        lines.append("## Recommendations")
        if ctx.ai_report:
            for r in ctx.ai_report.get("recommendations", []):
                lines.append(f"- {r}")
        lines.append("")
        lines.append("---")
        lines.append("*Report generated by Jazz Platform*")
        return "\n".join(lines)

    def _generate_html(self, ctx):
        scores_html = "".join(
            f'<div class="score-item"><span class="score-label">{k}</span><div class="score-bar"><div class="score-fill" style="width:{v}%"></div></div><span class="score-val">{v}</span></div>'
            for k, v in sorted(ctx.risk_scores.items())
        )
        techs_html = "".join(
            f'<tr><td>{t["name"]}</td><td>{t["category"]}</td><td>{t["version"] or "-"}</td></tr>'
            for t in ctx.technologies
        )
        cves_html = "".join(
            f'<tr><td>{c["id"]}</td><td class="sev-{c["severity"].lower()}">{c["severity"]}</td><td>{c["score"]}</td><td>{c["description"][:80]}...</td></tr>'
            for c in ctx.cves[:10]
        )
        findings_html = "".join(
            f'<tr><td class="sev-{f["severity"].lower()}">{f["severity"]}</td><td>{f["title"]}</td></tr>'
            for f in ctx.findings
        )
        recs_html = "".join(f"<li>{r}</li>" for r in (ctx.ai_report.get("recommendations", []) if ctx.ai_report else []))
        overall = ctx.risk_scores.get("overall", 0) if ctx.risk_scores else 0
        sev_class = "critical" if overall < 40 else "high" if overall < 70 else "medium" if overall < 85 else "low"

        modules_html = ""
        if ctx.modules_findings:
            mod_sections = []
            for mod_name, mod_findings in ctx.modules_findings.items():
                rows = "".join(
                    f'<tr><td class="sev-{f.get("severity","info").lower()}">{f.get("severity","Info")}</td><td>{f.get("title","")[:60]}</td></tr>'
                    for f in mod_findings[:15]
                )
                mod_sections.append(
                    f'<h3>{mod_name} ({len(mod_findings)} findings)</h3>'
                    f'<table><tr><th>Severity</th><th>Title</th></tr>{rows}</table>'
                )
            modules_html = "<h2>Module Findings</h2>" + "".join(mod_sections)

        exploit_html = ""
        if ctx.exploitation_guide:
            exploit_items = []
            for eg in ctx.exploitation_guide:
                steps_html = "".join(f"<li>{s}</li>" for s in eg.get("exploit_steps", []))
                exploit_items.append(f"""
<div class="exploit-card">
  <div class="exploit-title">{eg.get('finding','')}</div>
  <div class="exploit-meta">Type: {eg.get('type','')}</div>
  <div class="exploit-cmd">$ {eg.get('curl_command','')}</div>
  <div class="exploit-payload">{eg.get('payload','')}</div>
  <ol>{steps_html}</ol>
</div>""")
            exploit_html = '<h2>Exploitation Guide</h2>' + "".join(exploit_items)

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Jazz Report — {ctx.target}</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0d0d0d; color: #e0e0e0; max-width: 1000px; margin: 40px auto; padding: 0 20px; }}
h1 {{ color: #c02626; border-bottom: 2px solid #333; padding-bottom: 10px; }}
h2 {{ color: #88cc88; margin-top: 30px; }}
h3 {{ color: #88cc88; margin-top: 20px; font-size: 14px; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #333; font-size: 12px; }}
th {{ color: #888; font-size: 11px; text-transform: uppercase; }}
.sev-critica, .sev-critical {{ color: #ff4444; font-weight: bold; }}
.sev-alta, .sev-high {{ color: #ff7744; }}
.sev-media, .sev-medium {{ color: #ffcc44; }}
.sev-baixa, .sev-low {{ color: #aaa; }}
.score-card {{ background: #1a1a1a; border-radius: 8px; padding: 20px; margin: 20px 0; }}
.score-item {{ display: flex; align-items: center; gap: 12px; margin: 8px 0; }}
.score-label {{ width: 150px; font-size: 12px; text-transform: uppercase; color: #888; }}
.score-bar {{ flex: 1; height: 10px; background: #333; border-radius: 5px; overflow: hidden; }}
.score-fill {{ height: 100%; background: linear-gradient(90deg, #c02626, #ffcc44, #88cc88); border-radius: 5px; transition: width 0.5s; }}
.score-val {{ width: 30px; text-align: right; font-weight: bold; }}
.overall {{ font-size: 48px; font-weight: 900; text-align: center; padding: 30px; }}
.overall.critical {{ color: #ff4444; }}
.overall.high {{ color: #ff7744; }}
.overall.medium {{ color: #ffcc44; }}
.overall.low {{ color: #88cc88; }}
ul {{ list-style: none; padding: 0; }}
li {{ padding: 6px 0; font-size: 12px; }}
li::before {{ content: "→ "; color: #88cc88; }}
.exploit-card {{ background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 12px; margin: 10px 0; }}
.exploit-title {{ color: #ffcc44; font-weight: bold; font-size: 13px; }}
.exploit-meta {{ color: #888; font-size: 11px; margin: 4px 0; }}
.exploit-cmd {{ background: #111; color: #88cc88; padding: 6px 10px; border-radius: 4px; font-family: monospace; font-size: 12px; margin: 6px 0; overflow-x: auto; }}
.exploit-payload {{ background: #111; color: #ff7744; padding: 6px 10px; border-radius: 4px; font-family: monospace; font-size: 11px; margin: 6px 0; }}
.footer {{ margin-top: 40px; font-size: 11px; color: #555; text-align: center; }}
</style></head><body>
<h1>Jazz Report</h1>
<p><strong>Target:</strong> {ctx.target} | <strong>IP:</strong> {ctx.target_ip} | <strong>Date:</strong> {datetime.now().isoformat()}</p>
<div class="overall {sev_class}">{overall}/100</div>
<h2>Risk Scores</h2><div class="score-card">{scores_html}</div>
<h2>Technologies</h2><table><tr><th>Name</th><th>Category</th><th>Version</th></tr>{techs_html}</table>
<h2>CVEs</h2><table><tr><th>CVE</th><th>Severity</th><th>Score</th><th>Description</th></tr>{cves_html}</table>
<h2>Findings (Pipeline)</h2><table><tr><th>Severity</th><th>Title</th></tr>{findings_html}</table>
{modules_html}
{exploit_html}
<h2>Recommendations</h2><ul>{recs_html}</ul>
<div class="footer">Generated by Jazz Platform</div>
</body></html>"""
