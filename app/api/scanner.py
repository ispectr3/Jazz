from flask import Blueprint, request, jsonify
from app.tasks.scanner_tasks import (
    run_maryam_osint,
    run_inurlbr_dorking,
    run_e4gl30s1nt_osint,
    run_mrholmes_recon,
    run_full_scan,
)
from app.tasks.caesar_tasks import run_caesarosint
from app.tasks.scanner_tasks import run_robots_analyzer, run_prompt_inject

scanner_bp = Blueprint('scanner', __name__)

ENGINE_MAP = {
    'maryam': run_maryam_osint,
    'inurlbr': run_inurlbr_dorking,
    'e4gl30s1nt': run_e4gl30s1nt_osint,
    'mrholmes': run_mrholmes_recon,
    'e4gl30': run_e4gl30s1nt_osint,
    'caesar': run_caesarosint,
    'cs': run_caesarosint,
    'caesarosint': run_caesarosint,
    'robots': run_robots_analyzer,
    'robotsanalyzer': run_robots_analyzer,
    'ra': run_robots_analyzer,
    'promptinject': run_prompt_inject,
    'pi': run_prompt_inject,
}

@scanner_bp.route('/scan', methods=['POST'])
def trigger_scan():
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "Target é obrigatorio"}), 400

    target = data['target']
    project_id = data.get('project_id', 1)
    command_str = data.get('command', '').lower()

    words = command_str.split()
    if len(words) >= 2 and words[0] in ENGINE_MAP:
        engine = words[0]
        engine_task = ENGINE_MAP[engine]
        engine_target = words[1] if len(words) > 1 else target
        print(f"Triggering {engine.upper()} no alvo: {engine_target}")
        try:
            async_res = engine_task.delay(engine_target, project_id)
            return jsonify({
                "status": "success",
                "message": f"{engine.upper()} disparado para {engine_target}.",
                "target": engine_target,
                "type": engine,
                "task_id": async_res.id,
            }), 200
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"{engine.upper()} falhou: {e}",
            }), 500

    if command_str.startswith('fullscan') or command_str.startswith('full'):
        return _start_fullscan(target, project_id)

    if command_str.startswith('dork') or command_str.startswith('inurlbr'):
        scan_target = words[1] if len(words) > 1 else target
        print(f"[INURLBR] Disparado contra: {scan_target}")
        try:
            async_res = run_inurlbr_dorking.delay(scan_target, project_id)
            return jsonify({
                "status": "success",
                "message": f"INURLBR disparado contra {scan_target}.",
                "target": scan_target,
                "type": "dork",
                "task_id": async_res.id,
            }), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return _start_fullscan(target, project_id)

@scanner_bp.route('/fullscan', methods=['POST'])
def fullscan():
    data = request.get_json()
    target = data.get('target') if data else None
    if not target:
        return jsonify({"error": "Target é obrigatorio"}), 400
    return _start_fullscan(target, data.get('project_id', 1))

def _start_fullscan(target, project_id):
    print(f"[FullScan] Disparando todas as engines contra: {target}")
    async_res = run_full_scan.delay(target, project_id)
    return jsonify({
        "status": "success",
        "message": f"Full scan disparado para {target}. Tasks em paralelo.",
        "target": target,
        "type": "fullscan",
        "task_id": async_res.id,
    }), 200
