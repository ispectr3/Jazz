#!/usr/bin/env python3
"""
Suíte de teste de acurácia para JazzNoir.

Uso:
  python scripts/test_accuracy.py --target dvwa
  python scripts/test_accuracy.py --target juice-shop
  python scripts/test_accuracy.py --target all
  python scripts/test_accuracy.py --list-targets

Compara findings do pipeline contra alvos vulneráveis conhecidos.
Métricas: precisão, recall, F1, taxa de alucinação.
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


TARGETS = {
    "dvwa": {
        "url": "http://localhost:42801",
        "name": "Damn Vulnerable Web Application",
        "expected_findings": [
            "SQL Injection",
            "XSS",
            "CSRF",
            "File Inclusion",
            "File Upload",
        ],
        "expected_techs": ["PHP", "MySQL", "Apache"],
        "min_findings": 3,
    },
    "juice-shop": {
        "url": "http://localhost:42802",
        "name": "OWASP Juice Shop",
        "expected_findings": [
            "Score Board",
            "SQL Injection",
            "XSS",
            "Broken Authentication",
        ],
        "expected_techs": ["Express", "Node.js", "Angular"],
        "min_findings": 3,
    },
    "webgoat": {
        "url": "http://localhost:42803/WebGoat",
        "name": "WebGoat",
        "expected_findings": [
            "SQL Injection",
            "XSS",
            "Authentication Bypass",
        ],
        "expected_techs": ["Java", "Spring"],
        "min_findings": 2,
    },
}


@dataclass
class AccuracyMetrics:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    total_expected: int = 0
    total_found: int = 0
    hallucination_count: int = 0
    validated_count: int = 0
    unvalidated_count: int = 0
    execution_time_s: float = 0.0

    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        if self.total_expected == 0:
            return 0.0
        return self.true_positives / self.total_expected

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def hallucination_rate(self) -> float:
        if self.total_found == 0:
            return 0.0
        return self.hallucination_count / self.total_found

    def to_dict(self) -> dict:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "total_expected": self.total_expected,
            "total_found": self.total_found,
            "hallucination_count": self.hallucination_count,
            "validated_count": self.validated_count,
            "unvalidated_count": self.unvalidated_count,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1_score": round(self.f1, 3),
            "hallucination_rate": round(self.hallucination_rate, 3),
            "execution_time_s": round(self.execution_time_s, 2),
        }


def check_target_alive(url: str, timeout: int = 10) -> bool:
    import urllib.request
    try:
        req = urllib.request.Request(url, method="HEAD")
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        try:
            req = urllib.request.Request(url)
            urllib.request.urlopen(req, timeout=timeout)
            return True
        except Exception:
            return False


def run_pipeline(target_url: str) -> dict:
    from app.pipeline.engine import Pipeline
    from app.pipeline.phases import ReconPhase, FingerprintPhase, CVEPhase
    from app.pipeline.phase_web_and_risk import WebPhase, RiskScorePhase
    from app.pipeline.phase_orchestrator import OrchestratorPhase

    pipeline = Pipeline()
    pipeline.add_phase(ReconPhase())
    pipeline.add_phase(FingerprintPhase())
    pipeline.add_phase(OrchestratorPhase())
    pipeline.add_phase(CVEPhase())
    pipeline.add_phase(WebPhase())
    pipeline.add_phase(RiskScorePhase())

    import asyncio
    ctx = asyncio.run(pipeline.execute(target_url, project_id=9999, max_iterations=1))

    result = ctx.to_dict()
    result["grounding"] = getattr(ctx, "grounding_report", {})
    result["hallucination_risk"] = getattr(ctx, "hallucination_risk", 0)
    result["technologies"] = ctx.technologies
    return result


def evaluate_results(target_key: str, result: dict) -> AccuracyMetrics:
    target_info = TARGETS[target_key]
    metrics = AccuracyMetrics()
    metrics.total_expected = len(target_info["expected_findings"])

    finding_titles = []
    for mod, findings in result.get("modules_findings", {}).items():
        for f in findings:
            title = f.get("title", f.get("name", ""))
            finding_titles.append(title.lower())

    for f in result.get("findings", []):
        title = f.get("title", "")
        finding_titles.append(title.lower())

    found_expected = set()
    for expected in target_info["expected_findings"]:
        exp_lower = expected.lower()
        matched = False
        for title in finding_titles:
            if exp_lower in title:
                matched = True
                found_expected.add(expected)
                break
        if matched:
            metrics.true_positives += 1
        else:
            metrics.false_negatives += 1

    grounding = result.get("grounding", {})
    metrics.validated_count = grounding.get("validated_count", 0)
    metrics.unvalidated_count = grounding.get("unvalidated_count", 0)
    metrics.total_found = grounding.get("total_findings", len(finding_titles))
    metrics.hallucination_count = metrics.unvalidated_count

    return metrics


def print_report(target_key: str, metrics: AccuracyMetrics):
    name = TARGETS[target_key]['name'] if target_key in TARGETS else target_key.title()
    print(f"\n{'='*50}")
    print(f"Target: {target_key} ({name})")
    print(f"{'='*50}")
    print(f"  True Positives:  {metrics.true_positives}/{metrics.total_expected}")
    print(f"  False Negatives: {metrics.false_negatives}")
    print(f"  Total Findings:  {metrics.total_found}")
    print(f"  Validated:       {metrics.validated_count}")
    print(f"  Unvalidated:     {metrics.unvalidated_count}")
    print(f"  Hallucination:   {metrics.hallucination_count}")
    print(f"  {'─'*40}")
    print(f"  Precision:       {metrics.precision:.1%}")
    print(f"  Recall:          {metrics.recall:.1%}")
    print(f"  F1 Score:        {metrics.f1:.3f}")
    print(f"  Hallucination:   {metrics.hallucination_rate:.1%}")
    print(f"  Time:            {metrics.execution_time_s:.1f}s")


def main():
    parser = argparse.ArgumentParser(description="JazzNoir Accuracy Test Suite")
    parser.add_argument("--target", choices=list(TARGETS.keys()) + ["all"], default="all")
    parser.add_argument("--list-targets", action="store_true", help="List available targets")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    if args.list_targets:
        print("Available targets:")
        for key, info in TARGETS.items():
            print(f"  {key:15s} {info['name']:35s} {info['url']}")
        return

    targets = list(TARGETS.keys()) if args.target == "all" else [args.target]

    all_results = {}

    for target_key in targets:
        target_info = TARGETS[target_key]
        print(f"\nChecking {target_info['name']} at {target_info['url']}...")

        if not check_target_alive(target_info["url"]):
            print(f"  SKIP: target not reachable. Start with: docker compose up -d")
            all_results[target_key] = {"error": "unreachable", "metrics": {}}
            continue

        start = time.time()
        try:
            result = run_pipeline(target_info["url"])
            elapsed = time.time() - start
            metrics = evaluate_results(target_key, result)
            metrics.execution_time_s = elapsed
            print_report(target_key, metrics)
            all_results[target_key] = {
                "target": target_info["name"],
                "url": target_info["url"],
                "metrics": metrics.to_dict(),
            }
        except Exception as e:
            elapsed = time.time() - start
            print(f"  ERROR: {e}")
            all_results[target_key] = {"error": str(e), "metrics": {}}

    summary = AccuracyMetrics()
    for key, data in all_results.items():
        m = data.get("metrics", {})
        summary.true_positives += m.get("true_positives", 0)
        summary.false_positives += m.get("false_positives", 0)
        summary.false_negatives += m.get("false_negatives", 0)
        summary.total_expected += m.get("total_expected", 0)
        summary.total_found += m.get("total_found", 0)
        summary.hallucination_count += m.get("hallucination_count", 0)
        summary.validated_count += m.get("validated_count", 0)
        summary.unvalidated_count += m.get("unvalidated_count", 0)

    print(f"\n{'='*50}")
    print(f"SUMMARY - All Targets")
    print(f"{'='*50}")
    print_report("all", summary)

    all_results["_summary"] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "metrics": summary.to_dict(),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        print(f"\nReport saved to: {args.output}")


if __name__ == "__main__":
    main()
