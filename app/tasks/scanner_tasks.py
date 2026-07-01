from app.extensions import celery_app, db
from app.models.base import Project, Finding
from app.plugins.maryam_adapter import MaryamAdapter
from app.plugins.inurlbr_adapter import InurlbrAdapter
from app.plugins.e4gl30s1nt_adapter import E4gl30s1ntAdapter
from app.plugins.mrholmes_adapter import MrHolmesAdapter
from app.plugins.robots_adapter import RobotsAdapter
from app.plugins.promptinject_adapter import PromptInjectAdapter
from app.tasks.caesar_tasks import run_caesarosint
from app.ai.claude_bughunter import analyze_scope, build_report
from celery.result import AsyncResult
import subprocess
import os

MARYAM = MaryamAdapter()
INURLBR = InurlbrAdapter()
E4GL30 = E4gl30s1ntAdapter()
MRHOLMES = MrHolmesAdapter()


def _ingest_findings(findings_list: list, project_id: int, plugin_source: str):
    created_ids = []
    for f_data in findings_list:
        exists = Finding.query.filter_by(
            project_id=f_data["project_id"],
            plugin_source=f_data["plugin_source"],
            title=f_data["title"],
        ).first()
        if exists:
            continue
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
                if new_sev in {"Crítica", "Alta", "Média", "Baixa", "Info"}:
                    finding.severity = new_sev
                if new_sev == "Critica":
                    finding.severity = "Crítica"
                if new_sev == "Media":
                    finding.severity = "Média"

        db.session.commit()

    return created_ids


@celery_app.task(name='scanner_tasks.run_maryam_osint')
def run_maryam_osint(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Maryam] Varredura OSINT no alvo: {target}...")
        try:
            findings_list = MARYAM.normalize(target, project_id)
            ids = _ingest_findings(findings_list, project_id, MARYAM.name)
            return f"Sucesso: {len(ids)} findings."
        except Exception as e:
            return f"Erro: {e}"


@celery_app.task(name='scanner_tasks.run_inurlbr_dorking')
def run_inurlbr_dorking(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[INURLBR] Escaneando paths no alvo: {target}...")
        try:
            findings_list = INURLBR.normalize(target, project_id)
            ids = _ingest_findings(findings_list, project_id, INURLBR.name)
            print(f"[INURLBR] Scan concluido. {len(ids)} itens.")
            return f"Sucesso: {len(ids)} findings."
        except Exception as e:
            print(f"[INURLBR] Erro: {e}")
            return f"Erro: {e}"


@celery_app.task(name='scanner_tasks.run_e4gl30s1nt_osint')
def run_e4gl30s1nt_osint(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[E4GL30S1NT] Iniciando OSINT no alvo: {target}...")
        try:
            findings_list = E4GL30.normalize(target, project_id)
            ids = _ingest_findings(findings_list, project_id, E4GL30.name)
            return f"E4GL30S1NT OK: {len(ids)} findings."
        except Exception as e:
            return f"Erro E4GL30S1NT: {e}"


@celery_app.task(name='scanner_tasks.run_mrholmes_recon')
def run_mrholmes_recon(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Mr.Holmes] Iniciando recon no alvo: {target}...")
        try:
            findings_list = MRHOLMES.normalize(target, project_id)
            ids = _ingest_findings(findings_list, project_id, MRHOLMES.name)
            return f"Mr.Holmes OK: {len(ids)} findings."
        except Exception as e:
            return f"Erro Mr.Holmes: {e}"


@celery_app.task(name='scanner_tasks.run_robots_analyzer')
def run_robots_analyzer(domain: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[RobotsAnalyzer] Analisando robots.txt de: {domain}...")
        tool_dir = os.path.join(os.getcwd(), '.tools', 'RobotsAnalyzer')
        command = ["python3", "robots.py", "-d", domain, "--json"]
        try:
            result = subprocess.run(command, cwd=tool_dir, capture_output=True, text=True, check=False)
            adapter = RobotsAdapter()
            if adapter.validate_input(result.stdout):
                findings_list = adapter.normalize(result.stdout, project_id)
                ids = _ingest_findings(findings_list, project_id, adapter.name)
                return f"RobotsAnalyzer OK: {len(ids)} findings."
            return "Falha no parser RobotsAnalyzer."
        except Exception as e:
            return f"Erro RobotsAnalyzer: {e}"


@celery_app.task(name='scanner_tasks.run_prompt_inject')
def run_prompt_inject(target_api: str, project_id: int, system_prompt: str = None):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        sp = system_prompt or "You are a helpful security assistant. Always respond in JSON."
        print(f"[PromptInjector] Testando injecao de prompt em: {target_api}...")
        tool_dir = os.path.join(os.getcwd(), '.tools', 'PromptInjector')
        command = ["python3", "promptinject.py", "--api", target_api, "--system", sp, "--sample", "5", "--json"]
        try:
            result = subprocess.run(command, cwd=tool_dir, capture_output=True, text=True, check=False)
            adapter = PromptInjectAdapter()
            if adapter.validate_input(result.stdout):
                findings_list = adapter.normalize(result.stdout, project_id)
                ids = _ingest_findings(findings_list, project_id, adapter.name)
                return f"PromptInjector OK: {len(ids)} findings."
            return "Falha no parser PromptInjector."
        except Exception as e:
            return f"Erro PromptInjector: {e}"


@celery_app.task(name='scanner_tasks.run_full_scan')
def run_full_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"

        engines = [
            ("Maryam", run_maryam_osint, target),
            ("E4GL30S1NT", run_e4gl30s1nt_osint, target),
            ("Mr.Holmes", run_mrholmes_recon, target),
            ("INURLBR", run_inurlbr_dorking, target),
            ("CaesarOSINT", run_caesarosint, target),
            ("RobotsAnalyzer", run_robots_analyzer, target),
        ]

        for name, task_fn, arg in engines:
            print(f"[FullScan] Disparando {name}...")
            task_fn.delay(arg, project_id)

        print(f"[FullScan] Concluido. {len(results)} engines executadas.")
        return f"Full scan concluido: {results}"
