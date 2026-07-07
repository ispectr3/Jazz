import json
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

from .engine import PipelinePhase

ALL_MODULES = []

def _load_modules():
    global ALL_MODULES
    if ALL_MODULES:
        return ALL_MODULES

    from app.plugins.maryam_adapter import MaryamAdapter
    from app.plugins.inurlbr_adapter import InurlbrAdapter
    from app.plugins.e4gl30s1nt_adapter import E4gl30s1ntAdapter
    from app.plugins.mrholmes_adapter import MrHolmesAdapter
    from app.plugins.naabu_adapter import NaabuAdapter
    from app.plugins.nuclei_adapter import NucleiAdapter
    from app.plugins.nmap_adapter import NmapXMLAdapter
    from app.plugins.supabomb_adapter import SupabombAdapter
    from app.plugins.specter_adapter import SPECTERAdapter
    from app.plugins.wasminator_adapter import WasminatorAdapter
    from app.plugins.badworker_adapter import BadWorkerAdapter
    from app.plugins.csrf_detector import CSRFDetector
    from app.plugins.wafbypass_adapter import WAFBypassAdapter

    ALL_MODULES = [
        ("Maryam", MaryamAdapter()),
        ("INURLBR", InurlbrAdapter()),
        ("E4GL30S1NT", E4gl30s1ntAdapter()),
        ("Mr.Holmes", MrHolmesAdapter()),
        ("Naabu", NaabuAdapter()),
        ("Nuclei", NucleiAdapter()),
        ("Nmap", NmapXMLAdapter()),
        ("Supabomb", SupabombAdapter()),
        ("SPECTER", SPECTERAdapter()),
        ("Wasminator", WasminatorAdapter()),
        ("BadWorker", BadWorkerAdapter()),
        ("CSRFDetector", CSRFDetector()),
        ("WAFBypass", WAFBypassAdapter()),
    ]
    return ALL_MODULES


def _run_module(name, adapter, target, project_id):
    try:
        if name in ("CSRFDetector", "WAFBypass"):
            input_data = json.dumps({"target": target, "urls": [f"https://{target}"]})
            return name, adapter.normalize(input_data, project_id)

        if hasattr(adapter, "run_scan") and callable(adapter.run_scan):
            raw = adapter.run_scan(target)
            if raw and hasattr(adapter, "validate_input") and adapter.validate_input(raw):
                return name, adapter.normalize(raw, project_id)
            return name, []

        return name, adapter.normalize(target, project_id)
    except Exception:
        return name, []


class LegacyModulesPhase(PipelinePhase):
    name = "legacy_modules"
    description = "Execução dos módulos de varredura (OSINT, Infra, Web)"

    async def run(self, ctx):
        target = ctx.target
        project_id = ctx.project_id
        modules = _load_modules()
        all_findings = []

        pool = ThreadPoolExecutor(max_workers=8)
        futures = {
            pool.submit(_run_module, name, adp, target, project_id): name
            for name, adp in modules
        }
        try:
            for future in as_completed(futures, timeout=30):
                name = futures[future]
                try:
                    _, findings = future.result(timeout=5)
                    if findings:
                        ctx.modules_findings[name] = findings
                        all_findings.extend(findings)
                except TimeoutError:
                    pass
                except Exception:
                    pass
        except TimeoutError:
            pass
        finally:
            pool.shutdown(wait=False)

        if not all_findings:
            return ctx

        findings_map = {}
        for f in all_findings:
            key = (f.get("title"), f.get("plugin_source"))
            if key not in findings_map:
                findings_map[key] = f

        from app.extensions import db
        from app.models.base import Finding

        created_ids = []
        for f in findings_map.values():
            exists = Finding.query.filter_by(
                project_id=f["project_id"],
                plugin_source=f["plugin_source"],
                title=f["title"],
            ).first()
            if exists:
                continue
            new_finding = Finding(
                project_id=f["project_id"],
                plugin_source=f["plugin_source"],
                title=f["title"],
                description=f.get("description", ""),
                severity=f.get("severity", "Info"),
                raw_data=f.get("raw_data", {}),
            )
            db.session.add(new_finding)
            db.session.flush()
            created_ids.append(new_finding.id)

        db.session.commit()

        if created_ids:
            batch = Finding.query.filter(Finding.id.in_(created_ids)).all()
            batch_data = [
                {"id": f.id, "title": f.title, "description": f.description, "plugin_source": f.plugin_source}
                for f in batch
            ]
            from app.ai.claude_bughunter import analyze_scope, build_report
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

        return ctx
