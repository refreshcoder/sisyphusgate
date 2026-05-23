from __future__ import annotations

from dataclasses import dataclass, field

from sisyphusgate.analyzer.frequency import FrequencyTracker
from sisyphusgate.analyzer.heuristics import analyze_heuristics
from sisyphusgate.analyzer.signatures import DEFAULT_SIGNATURES, Signature, load_signatures_from_file
from sisyphusgate.config import AnalyzerConfig
from sisyphusgate.gateway.session import Session
from sisyphusgate.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AnalysisResult:
    session_id: str
    protocol: str
    score: int = 0
    threat_level: str = "low"
    tags: list[str] = field(default_factory=list)
    is_high_frequency: bool = False
    frequency_count: int = 0


class AnalysisEngine:
    def __init__(self, config: AnalyzerConfig, signature_file: str | None = None):
        self._config = config
        self._frequency_tracker = FrequencyTracker(
            window_seconds=config.frequency.window_seconds,
            threshold=config.frequency.threshold,
        )

        if signature_file:
            self._signatures = load_signatures_from_file(signature_file)
        else:
            self._signatures = list(DEFAULT_SIGNATURES)

    @property
    def frequency_tracker(self) -> FrequencyTracker:
        return self._frequency_tracker

    def add_signature(self, signature: Signature) -> None:
        self._signatures.append(signature)

    async def analyze(self, session: Session) -> AnalysisResult:
        result = AnalysisResult(
            session_id=session.session_id,
            protocol=session.protocol,
        )

        if self._config.enable_signatures:
            sig_score, sig_tags = self._run_signatures(session)
            result.score += sig_score
            result.tags.extend(sig_tags)

        if self._config.enable_frequency:
            freq_count = self._frequency_tracker.record(session.remote_host)
            result.frequency_count = freq_count
            result.is_high_frequency = freq_count >= self._config.frequency.threshold
            freq_score = self._frequency_tracker.get_frequency_score(session.remote_host)
            result.score += freq_score

        if self._config.enable_heuristics:
            heur_score, heur_tags = analyze_heuristics(session)
            result.score += heur_score
            result.tags.extend(heur_tags)

        result.score = min(result.score, 100)
        result.threat_level = self._calculate_level(result.score)
        result.tags = list(set(result.tags))

        session.threat_score = result.score
        session.threat_level = result.threat_level

        logger.info(
            "analysis_complete",
            session_id=session.session_id,
            remote=session.remote_host,
            protocol=session.protocol,
            score=result.score,
            level=result.threat_level,
            tags=result.tags,
            high_freq=result.is_high_frequency,
        )

        return result

    def _run_signatures(self, session: Session) -> tuple[int, list[str]]:
        total_score = 0
        tags = []

        proto_signatures = [s for s in self._signatures if s.protocol == session.protocol or s.protocol == "*"]

        for sig in proto_signatures:
            if sig.matches(session.initial_data):
                total_score += sig.score
                tags.extend(sig.tags)

        return min(total_score, 100), tags

    def _calculate_level(self, score: int) -> str:
        t = self._config.threat_thresholds
        if score >= t.critical:
            return "critical"
        if score >= t.high:
            return "high"
        if score >= t.medium:
            return "medium"
        return "low"