from app.extensions import celery_app, db
from app.models.base import Project, Finding
from app.plugins.caesar_adapter import CaesarAdapter
from app.ai.claude_bughunter import analyze_scope, build_report

def _ingest_findings(findings_list: list, project_id: int, plugin_source: str):
    created_ids = []
    for f_data in findings_list:
        new_finding = Finding(
            project_id=f_data["project_id"],
            plugin_source=f_data["plugin_source"],
            title=f_data["title"],
            description=f_data["description"],
            severity=f_data["severity"],
            raw_data=f_data["raw_data"]
        )
        db.session.add(new_finding)
        db.session.flush()
        created_ids.append(new_finding.id)
    db.session.commit()

    if created_ids:
        batch = Finding.query.filter(Finding.id.in_(created_ids)).all()
        batch_data = [{"id": f.id, "title": f.title, "description": f.description, "plugin_source": f.plugin_source} for f in batch]
        analyses = analyze_scope(batch_data)
        for analysis in analyses:
            idx = analysis.get("index")
            if idx is not None and idx < len(batch):
                finding = batch[idx]
                report = build_report(analysis)
                finding.description = f"{finding.description}\n\n{report}"
                new_sev = str(analysis.get("severity", "")).strip().title()
                if new_sev in {"Critica", "Alta", "Media", "Baixa", "Info"}:
                    finding.severity = new_sev
        db.session.commit()
    return created_ids

@celery_app.task(name='scanner_tasks.run_caesarosint')
def run_caesarosint(target: str, project_id: int, module: str = None):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"

        print(f"[CaesarOSINT] Iniciando scan real no alvo: {target}...")

        try:
            adapter = CaesarAdapter()
            findings_list = adapter.normalize(target, project_id)
            if findings_list:
                ids = _ingest_findings(findings_list, project_id, adapter.name)
                return f"CaesarOSINT OK: {len(ids)} findings reais analisados pelo Claude-BugHunter."
            else:
                return "CaesarOSINT OK: Nenhum finding relevante encontrado."

        except Exception as e:
            return f"Erro CaesarOSINT: {e}"
