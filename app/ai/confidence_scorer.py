from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ConfidenceScore:
    score: float  # 0.0 to 1.0
    evidence_count: int = 0
    source_reliability: float = 0.5
    framework_match: float = 0.0
    cross_validated: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "evidence_count": self.evidence_count,
            "source_reliability": self.source_reliability,
            "framework_match": self.framework_match,
            "cross_validated": self.cross_validated,
            "notes": self.notes,
        }


SOURCE_RELIABILITY = {
    "cve_database": 0.9,
    "nmap": 0.85,
    "whatweb": 0.8,
    "nuclei": 0.75,
    "sqlmap": 0.8,
    "ffuf": 0.7,
    "supabomb": 0.6,
    "specter": 0.6,
    "wasminator": 0.6,
    "badworker": 0.65,
    "graphql": 0.7,
    "csrf_detector": 0.75,
    "wafbypass": 0.6,
    "general": 0.4,
    "ai_analysis": 0.5,
    "zap": 0.7,
    "burp": 0.8,
}

FRAMEWORK_WEIGHTS = {
    "mitre_attack": 0.3,
    "nist_csf": 0.2,
    "cwe": 0.25,
    "owasp": 0.25,
}


class ConfidenceScorer:
    def __init__(self):
        self._source_reliability = dict(SOURCE_RELIABILITY)

    def score_finding(self, finding: dict) -> ConfidenceScore:
        source = finding.get("source", "general").lower()
        evidence = finding.get("evidence", finding.get("raw_data", finding.get("details", "")))
        title = finding.get("title", "")
        description = finding.get("description", "")
        severity = finding.get("severity", "")

        source_rel = self._source_reliability.get(source, 0.4)

        evidence_count = 0
        if evidence and len(str(evidence)) > 10:
            evidence_count += 1
        if title and len(title) > 5:
            evidence_count += 1
        if description and len(description) > 20:
            evidence_count += 1

        framework_match = self._score_framework(finding)
        cross_validated = self._is_cross_validated(finding)

        raw_score = (
            source_rel * 0.4
            + min(evidence_count / 3.0, 1.0) * 0.3
            + framework_match * 0.2
            + (0.1 if cross_validated else 0)
        )

        score = min(1.0, max(0.0, raw_score))

        notes = []
        if source_rel < 0.5:
            notes.append(f"Low source reliability ({source})")
        if evidence_count < 2:
            notes.append("Insufficient evidence fields")
        if framework_match < 0.3:
            notes.append("No framework mapping")
        if cross_validated:
            notes.append("Cross-validated by multiple sources")

        return ConfidenceScore(
            score=score,
            evidence_count=evidence_count,
            source_reliability=source_rel,
            framework_match=framework_match,
            cross_validated=cross_validated,
            notes=notes,
        )

    def _score_framework(self, finding: dict) -> float:
        match_score = 0.0
        total_weight = 0.0

        if finding.get("mitre_attack"):
            match_score += FRAMEWORK_WEIGHTS["mitre_attack"]
            total_weight += FRAMEWORK_WEIGHTS["mitre_attack"]
        if finding.get("nist_csf"):
            match_score += FRAMEWORK_WEIGHTS["nist_csf"]
            total_weight += FRAMEWORK_WEIGHTS["nist_csf"]
        if finding.get("cwe"):
            match_score += FRAMEWORK_WEIGHTS["cwe"]
            total_weight += FRAMEWORK_WEIGHTS["cwe"]
        if finding.get("owasp"):
            match_score += FRAMEWORK_WEIGHTS["owasp"]
            total_weight += FRAMEWORK_WEIGHTS["owasp"]

        if total_weight > 0:
            return match_score / total_weight
        return 0.0

    def _is_cross_validated(self, finding: dict) -> bool:
        return bool(finding.get("cross_validated")) or bool(finding.get("validated_from_multiple_sources"))

    def should_suppress(self, finding: dict, threshold: float = 0.3) -> tuple[bool, ConfidenceScore]:
        cs = self.score_finding(finding)
        if cs.score < threshold:
            return True, cs
        return False, cs


class FrameworkAwareSuppressor:
    def __init__(self):
        self._scorer = ConfidenceScorer()
        self._suppression_rules: Dict[str, dict] = {}

    def add_rule(self, framework: str, pattern: str, max_confidence: float = 0.3):
        import re
        self._suppression_rules.setdefault(framework, {})[pattern] = max_confidence

    def _check_framework_suppression(self, finding: dict) -> Optional[str]:
        title = finding.get("title", "")
        desc = finding.get("description", "")
        text = f"{title} {desc}".lower()

        for framework, rules in self._suppression_rules.items():
            for pattern, threshold in rules.items():
                import re
                if re.search(pattern, text):
                    cs = self._scorer.score_finding(finding)
                    if cs.score < threshold:
                        return f"suppressed_by_{framework}_{pattern}"
        return None

    def evaluate(self, finding: dict, confidence_threshold: float = 0.3) -> dict:
        should_suppress_fp, cs = self._scorer.should_suppress(finding, confidence_threshold)

        framework_reason = self._check_framework_suppression(finding)

        suppression_reason = None
        if framework_reason:
            suppression_reason = framework_reason
        elif should_suppress_fp:
            suppression_reason = f"low_confidence_{cs.score:.2f}"

        return {
            "finding_title": finding.get("title", ""),
            "confidence": cs.to_dict(),
            "suppressed": suppression_reason is not None,
            "suppression_reason": suppression_reason or "",
            "suggested_action": "suppress" if suppression_reason else "include",
        }

    def batch_evaluate(self, findings: List[dict], confidence_threshold: float = 0.3) -> List[dict]:
        return [self.evaluate(f, confidence_threshold) for f in findings]
