from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models.base import Project, Finding
from datetime import datetime

scanner_bp = Blueprint('scanner', __name__)

ALL_ENGINES = [
    {"id": "maryam", "name": "Maryam", "category": "OSINT", "description": "OSINT framework multi-fontes"},
    {"id": "inurlbr", "name": "INURLBR", "category": "OSINT", "description": "Dorking e busca avançada"},
    {"id": "e4gl30s1nt", "name": "E4GL30S1NT", "category": "OSINT", "description": "OSINT automatizado"},
    {"id": "mrholmes", "name": "Mr.Holmes", "category": "OSINT", "description": "Recon completo"},
    {"id": "caesarosint", "name": "CaesarOSINT", "category": "OSINT", "description": "OSINT com IA"},
    {"id": "naabu", "name": "Naabu", "category": "Infra", "description": "Port scan rápido"},
    {"id": "nmap", "name": "Nmap", "category": "Infra", "description": "Port scan + service detection"},
    {"id": "nuclei", "name": "Nuclei", "category": "Infra", "description": "Varredura de vulnerabilidades"},
    {"id": "robots", "name": "RobotsAnalyzer", "category": "Web", "description": "Análise de robots.txt"},
    {"id": "supabomb", "name": "Supabomb", "category": "Web", "description": "Scanner Supabase"},
    {"id": "specter", "name": "SPECTER", "category": "Web", "description": "Scanner Wix"},
    {"id": "wasminator", "name": "Wasminator", "category": "Web", "description": "Análise WASM"},
    {"id": "promptinject", "name": "PromptInjector", "category": "AI", "description": "Injeção de prompt em LLMs"},
    {"id": "badworker", "name": "BadWorker", "category": "Web", "description": "Scanner de Web Workers"},
    {"id": "badworker-static", "name": "BadWorker (Static)", "category": "Web", "description": "Análise estática de workers"},
    {"id": "csrf", "name": "CSRFDetector", "category": "Web", "description": "Detector de CSRF em formulários"},
    {"id": "wafbypass", "name": "WAF Bypass", "category": "Web", "description": "Gerador de payloads WAF bypass"},
    {"id": "jwttool", "name": "JWTTool", "category": "Web", "description": "Auditoria de JWTs (none alg, brute-force, KID injection)"},
    {"id": "ffuf", "name": "Ffuf", "category": "Web", "description": "Fuzzing web (diretórios, parâmetros, subdomínios)"},
    {"id": "cascavel", "name": "Cascavel", "category": "Web", "description": "Scanner web completo (135 plugins)"},
    {"id": "cascavel-injection", "name": "Cascavel (Injection)", "category": "Web", "description": "Testes de injeção"},
    {"id": "cascavel-auth", "name": "Cascavel (Auth)", "category": "Web", "description": "Testes de autenticação"},
    {"id": "cascavel-api", "name": "Cascavel (API)", "category": "Web", "description": "Testes de API"},
    {"id": "cascavel-infra", "name": "Cascavel (Infra)", "category": "Infra", "description": "Testes de infraestrutura"},
    {"id": "cascavel-recon", "name": "Cascavel (Recon)", "category": "OSINT", "description": "Reconhecimento"},
    {"id": "pentestai", "name": "PentestAI", "category": "AI", "description": "Pentest com IA + scanners built-in"},
    {"id": "garak", "name": "Garak", "category": "AI", "description": "Scanner de vulnerabilidades LLM"},
    {"id": "promptfoo", "name": "Promptfoo", "category": "AI", "description": "Red-teaming de prompts"},
    {"id": "hiddenlayer", "name": "HiddenLayer", "category": "AI", "description": "MLDR e monitoramento de ML"},
    {"id": "foolbox", "name": "Foolbox", "category": "AI", "description": "Ataques adversariais (FGSM, PGD)"},
    {"id": "cleverhans", "name": "CleverHans", "category": "AI", "description": "Benchmarks adversariais"},
    {"id": "tfprivacy", "name": "TF Privacy", "category": "AI", "description": "Auditoria de privacidade diferencial"},
    {"id": "art", "name": "ART (IBM)", "category": "AI", "description": "Adversarial Robustness Toolbox"},
    {"id": "torchattacks", "name": "TorchAttacks", "category": "AI", "description": "Catálogo de ataques PyTorch"},
    {"id": "textattack", "name": "TextAttack", "category": "AI", "description": "Ataques adversariais em NLP"},
    {"id": "llmattacks", "name": "LLM-Attacks", "category": "AI", "description": "GCG + transfer attacks"},
    {"id": "runtimehooks", "name": "RuntimeHooks", "category": "Web", "description": "API hooks para runtime monitoring"},
    {"id": "pyrit", "name": "PyRIT", "category": "AI", "description": "Microsoft PyRIT — red teaming automatizado para IA generativa"},
    {"id": "llmguard", "name": "LLM Guard", "category": "AI", "description": "ProtectAI — gateway de seguranca para interacoes com LLM"},
    {"id": "rebuff", "name": "Rebuff", "category": "AI", "description": "ProtectAI — detector de prompt injection [ARCHIVED]"},
    {"id": "harmbench", "name": "HarmBench", "category": "AI", "description": "Center for AI Safety — benchmark de red teaming"},
    {"id": "promptbench", "name": "PromptBench", "category": "AI", "description": "Microsoft — framework de avaliacao de LLMs [ARCHIVED]"},
]

ENGINE_TASKS = {
    "maryam": ("app.tasks.scanner_tasks", "run_maryam_osint", ["target", "project_id"]),
    "inurlbr": ("app.tasks.scanner_tasks", "run_inurlbr_dorking", ["target", "project_id"]),
    "e4gl30s1nt": ("app.tasks.scanner_tasks", "run_e4gl30s1nt_osint", ["target", "project_id"]),
    "mrholmes": ("app.tasks.scanner_tasks", "run_mrholmes_recon", ["target", "project_id"]),
    "caesarosint": ("app.tasks.caesar_tasks", "run_caesarosint", ["target", "project_id"]),
    "naabu": ("app.tasks.scanner_tasks", "run_naabu_portscan", ["target", "project_id"]),
    "nmap": ("app.tasks.scanner_tasks", "run_nmap_scan", ["target", "project_id"]),
    "nuclei": ("app.tasks.scanner_tasks", "run_nuclei_scan", ["target", "project_id"]),
    "robots": ("app.tasks.scanner_tasks", "run_robots_analyzer", ["target", "project_id"]),
    "supabomb": ("app.tasks.scanner_tasks", "run_supabomb_scan", ["target", "project_id"]),
    "specter": ("app.tasks.scanner_tasks", "run_specter_scan", ["target", "project_id"]),
    "wasminator": ("app.tasks.scanner_tasks", "run_wasminator_scan", ["target", "project_id"]),
    "promptinject": ("app.tasks.scanner_tasks", "run_prompt_inject", ["target", "project_id"]),
    "badworker": ("app.tasks.scanner_tasks", "run_badworker_scan", ["target", "project_id"]),
    "badworker-static": ("app.tasks.scanner_tasks", "run_badworker_static", ["project_id"]),
    "csrf": ("app.tasks.scanner_tasks", "run_csrf_scan", ["target", "project_id"]),
    "wafbypass": ("app.tasks.scanner_tasks", "run_wafbypass_scan", ["target", "project_id"]),
    "jwttool": ("app.tasks.scanner_tasks", "run_jwttool_scan", ["target", "project_id"]),
    "ffuf": ("app.tasks.scanner_tasks", "run_ffuf_fuzz", ["target", "project_id"]),
    "cascavel": ("app.tasks.scanner_tasks", "run_cascavel_scan", ["target", "project_id"]),
    "cascavel-injection": ("app.tasks.scanner_tasks", "run_cascavel_category", ["target", "project_id", "injection"]),
    "cascavel-auth": ("app.tasks.scanner_tasks", "run_cascavel_category", ["target", "project_id", "auth"]),
    "cascavel-api": ("app.tasks.scanner_tasks", "run_cascavel_category", ["target", "project_id", "api"]),
    "cascavel-infra": ("app.tasks.scanner_tasks", "run_cascavel_category", ["target", "project_id", "infra"]),
    "cascavel-recon": ("app.tasks.scanner_tasks", "run_cascavel_category", ["target", "project_id", "recon"]),
    "pentestai": ("app.tasks.scanner_tasks", "run_pentestai_scan", ["target", "project_id"]),
    "garak": ("app.tasks.scanner_tasks", "run_garak_scan", ["openai", "gpt-3.5-turbo", "project_id"]),
    "promptfoo": ("app.tasks.scanner_tasks", "run_promptfoo_eval", ["target", "project_id"]),
    "hiddenlayer": ("app.tasks.scanner_tasks", "run_hiddenlayer_monitor", ["project_id", "llm", "target"]),
    "foolbox": ("app.tasks.scanner_tasks", "run_foolbox_attack", ["project_id"]),
    "cleverhans": ("app.tasks.scanner_tasks", "run_cleverhans_benchmark", ["project_id"]),
    "tfprivacy": ("app.tasks.scanner_tasks", "run_tfprivacy_audit", ["project_id"]),
    "art": ("app.tasks.scanner_tasks", "run_art_scan", ["project_id"]),
    "torchattacks": ("app.tasks.scanner_tasks", "run_torchattacks_scan", ["project_id"]),
    "textattack": ("app.tasks.scanner_tasks", "run_textattack_scan", ["project_id"]),
    "llmattacks": ("app.tasks.scanner_tasks", "run_llmattacks_scan", ["target", "project_id"]),
    "runtimehooks": ("app.tasks.scanner_tasks", "run_runtimehooks_scan", ["target", "project_id"]),
    "pyrit": ("app.tasks.scanner_tasks", "run_pyrit_scan", ["target", "project_id"]),
    "llmguard": ("app.tasks.scanner_tasks", "run_llmguard_scan", ["target", "project_id"]),
    "rebuff": ("app.tasks.scanner_tasks", "run_rebuff_scan", ["project_id"]),
    "harmbench": ("app.tasks.scanner_tasks", "run_harmbench_eval", ["project_id"]),
    "promptbench": ("app.tasks.scanner_tasks", "run_promptbench_eval", ["project_id"]),
}


def _import_task(module_path, task_name):
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, task_name)

@scanner_bp.route('/engines', methods=['GET'])
def list_engines():
    return jsonify(ALL_ENGINES), 200

@scanner_bp.route('/engines/categories', methods=['GET'])
def list_categories():
    cats = {}
    for e in ALL_ENGINES:
        cat = e["category"]
        if cat not in cats:
            cats[cat] = []
        cats[cat].append(e["id"])
    return jsonify(cats), 200

@scanner_bp.route('/projects', methods=['GET'])
def list_projects():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return jsonify([{
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "created_at": p.created_at.isoformat() if p.created_at else None
    } for p in projects]), 200

@scanner_bp.route('/projects', methods=['POST'])
def create_project():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({"error": "Nome do projeto é obrigatorio"}), 400
    project = Project(
        name=data['name'],
        description=data.get('description', '')
    )
    db.session.add(project)
    db.session.commit()
    return jsonify({
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at.isoformat() if project.created_at else None
    }), 201

@scanner_bp.route('/projects/<int:project_id>', methods=['GET'])
def get_project(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Projeto não encontrado"}), 404
    return jsonify({
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "findings_count": Finding.query.filter_by(project_id=project_id).count()
    }), 200

@scanner_bp.route('/scan', methods=['POST'])
def trigger_scan():
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "Target é obrigatorio"}), 400

    target = data['target']
    project_id = data.get('project_id', 1)
    engines = data.get('engines', [])
    command_str = data.get('command', '').lower()

    if engines:
        return _dispatch_selected_engines(target, project_id, engines)

    words = command_str.split()
    if len(words) >= 2 and words[0] in ENGINE_TASKS:
        engine_id = words[0]
        engine_target = words[1] if len(words) > 1 else target
        return _dispatch_single_engine(engine_id, engine_target, project_id)

    if command_str.startswith('fullscan') or command_str.startswith('full'):
        return _start_fullscan(target, project_id)

    return _start_fullscan(target, project_id)

@scanner_bp.route('/fullscan', methods=['POST'])
def fullscan():
    data = request.get_json()
    target = data.get('target') if data else None
    if not target:
        return jsonify({"error": "Target é obrigatorio"}), 400
    return _start_fullscan(target, data.get('project_id', 1))

@scanner_bp.route('/scan/<int:project_id>/results', methods=['GET'])
def scan_results(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Projeto não encontrado"}), 404
    sources = db.session.query(
        Finding.plugin_source,
        db.func.count(Finding.id).label('total'),
        db.func.max(Finding.created_at).label('last_scan')
    ).filter_by(project_id=project_id).group_by(Finding.plugin_source).all()
    return jsonify([{
        "module": s.plugin_source,
        "total_findings": s.total,
        "last_scan": s.last_scan.isoformat() if s.last_scan else None
    } for s in sources]), 200

def _dispatch_selected_engines(target, project_id, engines):
    results = []
    for engine_id in engines:
        if engine_id not in ENGINE_TASKS:
            results.append({"engine": engine_id, "status": "skipped", "reason": "unknown_engine"})
            continue
        module_path, task_name, arg_spec = ENGINE_TASKS[engine_id]
        args = []
        for a in arg_spec:
            if a == "target":
                args.append(target)
            elif a == "project_id":
                args.append(project_id)
            else:
                args.append(a)
        try:
            task_fn = _import_task(module_path, task_name)
            async_res = task_fn.delay(*args)
            results.append({"engine": engine_id, "status": "dispatched", "task_id": async_res.id})
        except Exception as e:
            results.append({"engine": engine_id, "status": "error", "error": str(e)})
    return jsonify({
        "status": "success",
        "target": target,
        "project_id": project_id,
        "engines": results,
        "total": len(results),
        "dispatched": sum(1 for r in results if r["status"] == "dispatched")
    }), 200

def _dispatch_single_engine(engine_id, engine_target, project_id):
    if engine_id not in ENGINE_TASKS:
        return jsonify({"error": f"Engine desconhecida: {engine_id}"}), 400
    module_path, task_name, arg_spec = ENGINE_TASKS[engine_id]
    args = []
    for a in arg_spec:
        if a == "target":
            args.append(engine_target)
        elif a == "project_id":
            args.append(project_id)
        else:
            args.append(a)
    try:
        task_fn = _import_task(module_path, task_name)
        async_res = task_fn.delay(*args)
        return jsonify({
            "status": "success",
            "message": f"{engine_id.upper()} disparado para {engine_target}.",
            "target": engine_target,
            "type": engine_id,
            "task_id": async_res.id,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"{engine_id.upper()} falhou: {e}"}), 500

def _start_fullscan(target, project_id):
    task_fn = _import_task("app.tasks.scanner_tasks", "run_full_scan")
    async_res = task_fn.delay(target, project_id)
    return jsonify({
        "status": "success",
        "message": f"Full scan disparado para {target}. Tasks em paralelo.",
        "target": target,
        "type": "fullscan",
        "task_id": async_res.id,
    }), 200
