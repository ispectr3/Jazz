import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from datetime import datetime

from .engine import PipelinePhase
from app.ai.classifier import ToolClassifier
from app.ai.grounded_agent import GroundedPipeline


def _load_heavy_adapters():
    modules = []

    try:
        from app.plugins.nmap_adapter import NmapXMLAdapter
        modules.append(("Nmap", NmapXMLAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.supabomb_adapter import SupabombAdapter
        modules.append(("Supabomb", SupabombAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.specter_adapter import SPECTERAdapter
        modules.append(("SPECTER", SPECTERAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.wasminator_adapter import WasminatorAdapter
        modules.append(("Wasminator", WasminatorAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.badworker_adapter import BadWorkerAdapter
        modules.append(("BadWorker", BadWorkerAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.ffuf_adapter import FfufAdapter
        modules.append(("Ffuf", FfufAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.sqlmap_adapter import SQLMapAdapter
        modules.append(("SQLMap", SQLMapAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.graphql_scanner_adapter import GraphQLScannerAdapter
        modules.append(("GraphQL", GraphQLScannerAdapter()))
    except Exception:
        pass
    try:
        from app.plugins.whatweb_adapter import WhatWebAdapter
        modules.append(("WhatWeb", WhatWebAdapter()))
    except Exception:
        pass

    return modules


def _run_heavy_module(name, adapter, target, project_id):
    try:
        if not hasattr(adapter, "run_scan") or not callable(adapter.run_scan):
            return name, []
        raw = adapter.run_scan(target)
        if not raw:
            return name, []
        try:
            data = json.loads(raw)
            if "findings" in data and isinstance(data["findings"], list):
                for f in data["findings"]:
                    f.setdefault("project_id", project_id)
                    f.setdefault("plugin_source", f.get("plugin_source", name))
                return name, data["findings"]
        except (json.JSONDecodeError, TypeError):
            pass
        if hasattr(adapter, "validate_input") and adapter.validate_input(raw):
            return name, adapter.normalize(raw, project_id)
        return name, []
    except Exception:
        return name, []


class OrchestratorPhase(PipelinePhase):
    name = "orchestrator"
    description = "Orquestrador IA: decide ferramentas, executa scan pesado, analisa resultados"
    parallel_group = 1

    async def run(self, ctx):
        target = ctx.target
        project_id = ctx.project_id

        # 1. Decide which tools to run based on target context
        tools_to_run = self._decide_tools(ctx)

        if not tools_to_run:
            return ctx

        # 2. Run selected tools
        findings = await self._run_tools(tools_to_run, target, project_id)

        for name, mod_findings in findings.items():
            if mod_findings:
                ctx.modules_findings[name] = mod_findings

        # 2.5 Merge WhatWeb findings into ctx.technologies for CVEPhase
        whatweb_findings = findings.get("WhatWeb", [])
        for f in whatweb_findings:
            title = f.get("title", "")
            if title.startswith("Tecnologia:"):
                tech_name = title.split(":", 1)[1].strip()
                raw = f.get("raw_data", {})
                version = raw.get("version", "") if isinstance(raw, dict) else ""
                category = raw.get("category", "") if isinstance(raw, dict) else ""
                existing = [t for t in ctx.technologies if t["name"] == tech_name]
                if not existing:
                    ctx.technologies.append({
                        "name": tech_name,
                        "category": category,
                        "version": version,
                    })

        # 3. Analyze results with LLM
        await self._analyze_with_llm(ctx)

        # 4. Generate exploitation guidance
        ctx.exploitation_guide = self._build_exploitation_guide(ctx)

        return ctx

    def _decide_tools(self, ctx):
        classifier = ToolClassifier()
        tools = classifier.decide(ctx.target, ctx.technologies, ctx.findings)
        ctx.tools_selected = tools
        return tools

    async def _run_tools(self, tools, target, project_id):
        all_modules = _load_heavy_adapters()
        selected = [(n, a) for n, a in all_modules if n.lower() in [t.lower() for t in tools]]
        results = {}

        if not selected:
            return results

        monitor = self._get_monitor()
        agent_id = "orchestrator"

        for name, adapter in selected:
            check = monitor.check_tool_call(agent_id, name, target)
            if check and check["action"] in ("stop", "skip"):
                continue

            base_url = f"https://{target}"
            mod_target = target
            if name == "Ffuf":
                mod_target = f"{base_url}/FUZZ"
            elif name == "SQLMap":
                mod_target = base_url
            elif name == "GraphQL":
                mod_target = f"{base_url}/graphql"
            elif name == "WhatWeb":
                mod_target = base_url

            import time
            t0 = time.time()
            try:
                _, mod_findings = _run_heavy_module(name, adapter, mod_target, project_id)
                duration = int((time.time() - t0) * 1000)
                success = bool(mod_findings)
                monitor.record_result(agent_id, name, mod_target, success, duration)
                if mod_findings:
                    results[name] = mod_findings
            except Exception as e:
                duration = int((time.time() - t0) * 1000)
                monitor.record_result(agent_id, name, mod_target, False, duration)

        return results

    def _get_monitor(self):
        try:
            import asyncio
            for task in asyncio.all_tasks():
                coro = task.get_coro()
                if coro and hasattr(coro, "cr_frame") and coro.cr_frame:
                    ctx = coro.cr_frame.f_locals.get("ctx")
                    if ctx and hasattr(ctx, "execution_monitor") and ctx.execution_monitor:
                        return ctx.execution_monitor
        except Exception:
            pass
        from app.ai.execution_monitor import ExecutionMonitor
        return ExecutionMonitor.from_env()

    async def _analyze_with_llm(self, ctx):
        grounded = GroundedPipeline()
        report = grounded.process(ctx)

        ctx.grounding_report = report

        all_findings_text = []
        for f in report.get("validated_findings", []):
            all_findings_text.append(
                f"[{f.get('source', '?')}] [{f.get('severity', 'Info')}] {f.get('title', '')}: {f.get('description', '')[:200]}"
            )

        if not all_findings_text:
            return

        hallucination_warning = ""
        if report.get("hallucination_risk", 0) > 0.3:
            hallucination_warning = (
                f"\nWARNING: {report.get('unvalidated_count', 0)}/{report.get('total_findings', 0)} "
                "findings could not be validated. Do NOT include unvalidated data in your analysis."
            )

        prompt = f"""Target: {ctx.target}
IP: {ctx.target_ip}
Technologies: {[t['name'] for t in ctx.technologies]}
Total findings: {len(all_findings_text)}{hallucination_warning}

Validated findings ONLY:
{chr(10).join(all_findings_text[:30])}

Analyze these findings and return a JSON.
CRITICAL RULE: Only use data from the findings above. Do NOT invent or hallucinate vulnerabilities.
{{
  "critical_findings": ["list of most critical issues to exploit first"],
  "attack_vectors": ["possible attack chains"],
  "next_steps": ["recommended next tools or manual tests"],
  "exploitation_guide": [
    {{
      "finding": "name of finding",
      "type": "api|injection|misconfig|port|web|other",
      "curl_command": "curl command to test/probe",
      "payload": "example payload to try",
      "exploit_steps": ["step 1", "step 2"],
      "references": ["url1"]
    }}
  ]
}}"""

        from app.ai.agents import PentesterAgent, ReflectorAgent

        try:
            pentester = PentesterAgent()
            response = pentester.chat(
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.3,
            )
            parsed = json.loads(response)
            ctx.ai_analysis = {
                "critical_findings": parsed.get("critical_findings", []),
                "attack_vectors": parsed.get("attack_vectors", []),
                "next_steps": parsed.get("next_steps", []),
                "hallucination_risk": report.get("hallucination_risk", 0),
                "validated_findings": report.get("validated_count", 0),
                "unvalidated_findings": report.get("unvalidated_count", 0),
            }
            ctx.exploitation_guide = parsed.get("exploitation_guide", [])

            reflector = ReflectorAgent()
            quality_check = reflector.chat(
                messages=[{"role": "user", "content": f"Review this analysis for quality and hallucinations:\n{json.dumps(ctx.ai_analysis, indent=2)}"}],
                temperature=0.1,
            )
            ctx.ai_quality = quality_check
        except Exception:
            ctx.ai_analysis = {"critical_findings": [], "attack_vectors": [], "next_steps": [],
                               "hallucination_risk": report.get("hallucination_risk", 0),
                               "validated_findings": report.get("validated_count", 0),
                               "unvalidated_findings": report.get("unvalidated_count", 0)}
            ctx.exploitation_guide = []

    def _build_exploitation_guide(self, ctx):
        if hasattr(ctx, "exploitation_guide") and ctx.exploitation_guide:
            return ctx.exploitation_guide

        guide = []
        open_ports = set()
        for mod, findings in ctx.modules_findings.items():
            for f in findings:
                title = f.get("title", "")
                if "port" in title.lower():
                    import re

                    m = re.search(r"(\d+)", title)
                    if m:
                        open_ports.add(m.group(1))

        for port in sorted(open_ports):
            guide.append({
                "finding": f"Porta {port} aberta",
                "type": "port",
                "curl_command": f"curl -v http://{ctx.target}:{port}/",
                "payload": "",
                "exploit_steps": [
                    f"curl http://{ctx.target}:{port}/",
                    f"nmap -sV -p {port} {ctx.target}",
                    "Investigar servico na porta",
                ],
                "references": [],
            })

        base_url = f"https://{ctx.target}"
        guide.append({
            "finding": "Seguranca web geral",
            "type": "web",
            "curl_command": f"curl -v -X OPTIONS {base_url}/",
            "payload": "",
            "exploit_steps": [
                f"curl -v {base_url}/",
                f"curl -X OPTIONS {base_url}/ -v",
                f"ffuf -u {base_url}/FUZZ -w /usr/share/wordlists/common.txt",
            ],
            "references": [],
        })
        return guide
