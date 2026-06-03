from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
import re

from app.ai_detection import ai_detector
from app.detection import sql_injection_detector, Severity, AttackType


_BLOCKING_KEYWORDS = {
    "drop",
    "truncate",
    "alter",
    "grant",
    "revoke",
    "vacuum",
    "copy",
}


@dataclass
class QuerySandboxResult:
    query: str
    query_type: str
    threat_score: float
    risk_level: str
    blocked: bool
    explanation: str
    recommendation: str
    attack_type: Optional[str]
    severity: str
    confidence: float
    ai_prediction: str
    ai_confidence: float
    affected_tables: List[str]
    estimated_rows_affected: int
    estimated_cost: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class QuerySandbox:
    def analyze(self, query: str) -> QuerySandboxResult:
        normalized = self._normalize(query)
        detected = sql_injection_detector.detect(query)
        ai_result = ai_detector.predict(query)
        query_type = self._classify_query(normalized)
        affected_tables = self._extract_tables(query)

        threat_score = self._combine_scores(normalized, detected.severity, ai_result.threat_score)
        risk_level = self._risk_level(threat_score)
        blocked = self._should_block(normalized, detected, threat_score)
        explanation = self._build_explanation(normalized, detected, ai_result.prediction, affected_tables)
        recommendation = self._build_recommendation(risk_level, blocked)

        return QuerySandboxResult(
            query=query,
            query_type=query_type,
            threat_score=threat_score,
            risk_level=risk_level,
            blocked=blocked,
            explanation=explanation,
            recommendation=recommendation,
            attack_type=detected.attack_type.value if detected.attack_type else None,
            severity=detected.severity.value,
            confidence=detected.confidence,
            ai_prediction=ai_result.prediction,
            ai_confidence=ai_result.confidence,
            affected_tables=affected_tables,
            estimated_rows_affected=self._estimate_rows_affected(normalized, query_type),
            estimated_cost=self._estimate_cost(threat_score, query_type),
        )

    def _normalize(self, query: str) -> str:
        return re.sub(r"\s+", " ", query.strip()).lower()

    def _classify_query(self, normalized_query: str) -> str:
        for keyword in ("select", "insert", "update", "delete", "drop", "alter", "create", "grant", "revoke"):
            if normalized_query.startswith(keyword):
                return keyword
        if normalized_query.startswith("with "):
            return "select"
        return "unknown"

    def _extract_tables(self, query: str) -> List[str]:
        patterns = [
            r"(?i)\bfrom\s+([a-zA-Z0-9_\.\"`]+)",
            r"(?i)\bjoin\s+([a-zA-Z0-9_\.\"`]+)",
            r"(?i)\bupdate\s+([a-zA-Z0-9_\.\"`]+)",
            r"(?i)\binsert\s+into\s+([a-zA-Z0-9_\.\"`]+)",
            r"(?i)\bdelete\s+from\s+([a-zA-Z0-9_\.\"`]+)",
            r"(?i)\btruncate\s+table\s+([a-zA-Z0-9_\.\"`]+)",
        ]
        tables: List[str] = []
        for pattern in patterns:
            for match in re.findall(pattern, query):
                table = match.strip('"`')
                if table and table not in tables:
                    tables.append(table)
        return tables

    def _combine_scores(self, normalized_query: str, severity: Severity, ai_score: float) -> float:
        severity_weight = {
            Severity.CRITICAL: 0.95,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.55,
            Severity.LOW: 0.25,
            Severity.INFO: 0.05,
        }.get(severity, 0.1)

        destructive_bonus = 0.25 if any(keyword in normalized_query for keyword in _BLOCKING_KEYWORDS) else 0.0
        obfuscation_bonus = 0.15 if ("--" in normalized_query or "/*" in normalized_query or "%" in normalized_query) else 0.0
        exfiltration_bonus = 0.2 if "union select" in normalized_query or "information_schema" in normalized_query else 0.0
        score = max(severity_weight, ai_score)
        score = min(1.0, score + destructive_bonus + obfuscation_bonus + exfiltration_bonus)
        return round(score, 3)

    def _risk_level(self, score: float) -> str:
        if score >= 0.85:
            return "critical"
        if score >= 0.65:
            return "high"
        if score >= 0.35:
            return "medium"
        return "safe"

    def _should_block(self, normalized_query: str, detected, threat_score: float) -> bool:
        if threat_score >= 0.85:
            return True
        if detected.is_malicious and detected.severity in (Severity.CRITICAL, Severity.HIGH):
            return True
        if any(keyword in normalized_query for keyword in ("drop table", "truncate table", "delete from", "grant ", "revoke ")):
            return True
        return False

    def _build_explanation(self, normalized_query: str, detected, ai_prediction: str, tables: List[str]) -> str:
        reasons: List[str] = []
        if detected.attack_type == AttackType.UNION_BASED:
            reasons.append("UNION-based extraction pattern detected")
        if detected.attack_type == AttackType.TIME_BASED:
            reasons.append("time-delay payload detected")
        if detected.attack_type == AttackType.STACKED_QUERY:
            reasons.append("stacked statement injection detected")
        if "information_schema" in normalized_query:
            reasons.append("query targets schema metadata")
        if any(keyword in normalized_query for keyword in ("drop table", "truncate table", "delete from")):
            reasons.append("destructive data operation detected")
        if "or 1=1" in normalized_query or "tautology" in detected.details.lower():
            reasons.append("tautology bypass pattern detected")
        if ai_prediction == "malicious":
            reasons.append("AI classifier marked the payload as malicious")
        if tables:
            reasons.append(f"targets tables: {', '.join(tables[:3])}")
        return "; ".join(reasons) if reasons else "No high-risk behavior detected"

    def _build_recommendation(self, risk_level: str, blocked: bool) -> str:
        if blocked:
            return "Block the query, alert admins, and require manual review."
        if risk_level == "high":
            return "Review the query, enforce parameterization, and verify the tenant scope."
        if risk_level == "medium":
            return "Allow only after sandbox simulation and capability validation."
        return "Query can proceed through parameterized execution."

    def _estimate_rows_affected(self, normalized_query: str, query_type: str) -> int:
        # Slightly smarter heuristics including Mongo-like payloads
        try:
            # JSON-like queries often indicate Mongo operations
            if normalized_query.strip().startswith('{') or normalized_query.strip().startswith('['):
                # look for equality on _id or indexed fields
                if '"_id"' in normalized_query or "'_id'" in normalized_query:
                    return 1
                # simple key equality queries
                if ':' in normalized_query and '"$' not in normalized_query:
                    return 10
                return 100
        except Exception:
            pass

        if query_type in {"drop", "truncate"}:
            return 10000
        if query_type in {"update", "delete"}:
            return 1000 if "where" not in normalized_query else 10
        if query_type == "select" and "join" in normalized_query:
            return 250
        return 1

    def _estimate_cost(self, threat_score: float, query_type: str) -> str:
        if threat_score >= 0.85 or query_type in {"drop", "truncate"}:
            return "critical"
        if threat_score >= 0.65 or query_type in {"update", "delete"}:
            return "high"
        if threat_score >= 0.35:
            return "medium"
        return "low"


query_sandbox = QuerySandbox()