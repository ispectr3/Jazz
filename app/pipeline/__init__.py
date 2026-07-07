from .engine import Pipeline
from .phases import ReconPhase, FingerprintPhase, CVEPhase
from .phase_web_and_risk import WebPhase, RiskScorePhase
from .phase_ai_and_report import AIAnalysisPhase, ReportPhase
from .phase_legacy_modules import LegacyModulesPhase
from .phase_orchestrator import OrchestratorPhase
from .phase_zap_mcp import ZAPMCPPhase


def create_pipeline() -> Pipeline:
    return (
        Pipeline()
        .add_phase(ReconPhase())
        .add_phase(FingerprintPhase())
        .add_phase(WebPhase())
        .add_phase(LegacyModulesPhase())
        .add_phase(OrchestratorPhase())
        .add_phase(ZAPMCPPhase())
        .add_phase(CVEPhase())
        .add_phase(RiskScorePhase())
        .add_phase(AIAnalysisPhase())
        .add_phase(ReportPhase())
    )
