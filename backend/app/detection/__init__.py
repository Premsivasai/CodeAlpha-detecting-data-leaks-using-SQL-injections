import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    UNION_BASED = "union_based"
    BOOLEAN_BASED = "boolean_based"
    ERROR_BASED = "error_based"
    TIME_BASED = "time_based"
    BLIND_SQL = "blind_sql"
    STACKED_QUERY = "stacked_query"
    TAUTOLOGY = "tautology"
    PIGGY_BACKED = "piggy_backed"
    COMMENT_INJECTION = "comment_injection"
    ORACLE = "oracle"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectionResult:
    is_malicious: bool
    attack_type: Optional[AttackType]
    severity: Severity
    confidence: float
    details: str
    detection_method: str


class SQLInjectionDetector:
    def __init__(self):
        self._init_patterns()
        self._init_keywords()

    def _init_patterns(self):
        self.patterns = {
            AttackType.UNION_BASED: [
                r'(?i)\bunion\s+(all\s+)?select\b',
                r'(?i)\bunion\s+(all\s+)?select\b.*\bfrom\b',
                r'(?i)union\s+select\s+.*into\s+(outfile|dumpfile)',
            ],
            AttackType.BOOLEAN_BASED: [
                r'(?i)(and|or)\s+[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+[\'"]?',
                r'(?i)\b(1|0)\s*=\s*\d+',
                r'(?i)(and|or)\s+\d+\s*=\s*\d+',
            ],
            AttackType.ERROR_BASED: [
                r'(?i)extractvalue\([^,]+,[^)]+\)',
                r'(?i)updatexml\([^,]+,[^)]+,[^)]+\)',
                r'(?i)floor\(rand\(\)\*2\)',
                r'(?i)count\(\*\).*group\s+by',
            ],
            AttackType.TIME_BASED: [
                r'(?i)(sleep|wait|delay)\s*\([^)]*\)',
                r'(?i)benchmark\([^,]+,[^)]+\)',
                r'(?i)pg_sleep\s*\(',
                r'(?i)dbms_lock\.sleep',
            ],
            AttackType.BLIND_SQL: [
                r'(?i)(if|when)\s+.*\s*=\s*.*\s+then\b',
                r'(?i)waitfor\s+delay',
                r'(?i)(and|or)\s+\d+\s*>\s*\d+',
            ],
            AttackType.STACKED_QUERY: [
                r';\s*(select|insert|update|delete|drop|create|alter|exec|execute)',
                r';\s*\w+\s*--',
            ],
            AttackType.TAUTOLOGY: [
                r'(?i)(or|and)\s+1\s*=\s*1',
                r'(?i)(or|and)\s+[\'"]\s*[\'"]\s*=\s*[\'"]\s*[\'"]',
                r'(?i)\b(1|true|yes)\s*=\s*\1\b',
            ],
            AttackType.PIGGY_BACKED: [
                r'%0a\s*(select|insert|update|delete|drop)',
                r'%3b\s*(select|insert|update|delete|drop)',
                r'\n\s*(select|insert|update|delete|drop)',
            ],
            AttackType.COMMENT_INJECTION: [
                r'--\s*$',
                r'#\s*$',
                r'/\*.*\*/',
            ],
            AttackType.ORACLE: [
                r'(?i)utl_http\.request',
                r'(?i)dbms_sql\.execute',
                r'(?i)sys\.',
            ],
            AttackType.MYSQL: [
                r'(?i)information_schema',
                r'(?i)load_file\s*\(',
                r'(?i)into\s+(outfile|dumpfile)',
            ],
            AttackType.POSTGRESQL: [
                r'(?i)pg_',
                r'(?i)pg_catalog',
                r'(?i)copy\s+.*\s+from\s+stdin',
            ],
        }

    def _init_keywords(self):
        self.sql_keywords = {
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'union', 'from', 'where', 'join', 'order', 'by', 'group', 'having',
            'limit', 'offset', 'into', 'values', 'set', 'table', 'index',
            'database', 'schema', 'procedure', 'function', 'trigger', 'view'
        }

    def detect(self, query: str) -> DetectionResult:
        detections = []

        pattern_result = self._detect_patterns(query)
        if pattern_result:
            detections.append(pattern_result)

        keyword_result = self._detect_keywords(query)
        if keyword_result:
            detections.append(keyword_result)

        entropy_result = self._detect_entropy(query)
        if entropy_result:
            detections.append(entropy_result)

        encoding_result = self._detect_encoding(query)
        if encoding_result:
            detections.append(encoding_result)

        if not detections:
            return DetectionResult(
                is_malicious=False,
                attack_type=None,
                severity=Severity.INFO,
                confidence=0.0,
                details="Query passed all detection checks",
                detection_method="none"
            )

        max_severity = max(detections, key=lambda x: self._severity_weight(x.severity))
        avg_confidence = sum(d.confidence for d in detections) / len(detections)

        return DetectionResult(
            is_malicious=True,
            attack_type=max_severity.attack_type,
            severity=max_severity.severity,
            confidence=min(avg_confidence, 1.0),
            details=f"Detected {len(detections)} attack patterns",
            detection_method="multi_layer"
        )

    def _detect_patterns(self, query: str) -> Optional[DetectionResult]:
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, query):
                    return DetectionResult(
                        is_malicious=True,
                        attack_type=attack_type,
                        severity=self._get_severity(attack_type),
                        confidence=0.9,
                        details=f"Matched pattern for {attack_type.value}",
                        detection_method="regex"
                    )
        return None

    def _detect_keywords(self, query: str) -> Optional[DetectionResult]:
        words = re.findall(r'\w+', query.lower())
        keyword_count = sum(1 for w in words if w in self.sql_keywords)
        total_words = len(words)
        
        if total_words > 0:
            keyword_ratio = keyword_count / total_words
            
            if keyword_ratio > 0.5 and keyword_count >= 3:
                return DetectionResult(
                    is_malicious=False,
                    attack_type=None,
                    severity=Severity.LOW,
                    confidence=0.3,
                    details=f"High SQL keyword ratio: {keyword_ratio:.2f}",
                    detection_method="keyword_analysis"
                )

        return None

    def _detect_entropy(self, query: str) -> Optional[DetectionResult]:
        if len(query) == 0:
            return None
            
        import math
        freq = {}
        for char in query:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0
        for count in freq.values():
            prob = count / len(query)
            entropy -= prob * math.log2(prob)
        
        if entropy > 4.5:
            return DetectionResult(
                is_malicious=True,
                attack_type=None,
                severity=Severity.MEDIUM,
                confidence=0.6,
                details=f"High query entropy: {entropy:.2f}",
                detection_method="entropy_analysis"
            )
        
        return None

    def _detect_encoding(self, query: str) -> Optional[DetectionResult]:
        if '%' in query and len(query) > 3:
            return DetectionResult(
                is_malicious=False,
                attack_type=None,
                severity=Severity.LOW,
                confidence=0.2,
                details="URL encoding detected",
                detection_method="encoding_analysis"
            )
        
        if any(ord(c) > 127 for c in query):
            return DetectionResult(
                is_malicious=False,
                attack_type=None,
                severity=Severity.LOW,
                confidence=0.1,
                details="Non-ASCII characters detected",
                detection_method="encoding_analysis"
            )
        
        return None

    def _get_severity(self, attack_type: AttackType) -> Severity:
        severity_map = {
            AttackType.UNION_BASED: Severity.HIGH,
            AttackType.TIME_BASED: Severity.HIGH,
            AttackType.STACKED_QUERY: Severity.CRITICAL,
            AttackType.TAUTOLOGY: Severity.HIGH,
            AttackType.ERROR_BASED: Severity.MEDIUM,
            AttackType.BLIND_SQL: Severity.HIGH,
            AttackType.BOOLEAN_BASED: Severity.MEDIUM,
            AttackType.PIGGY_BACKED: Severity.CRITICAL,
            AttackType.COMMENT_INJECTION: Severity.MEDIUM,
            AttackType.ORACLE: Severity.HIGH,
            AttackType.MYSQL: Severity.HIGH,
            AttackType.POSTGRESQL: Severity.HIGH,
        }
        return severity_map.get(attack_type, Severity.MEDIUM)

    def _severity_weight(self, severity: Severity) -> int:
        weights = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights.get(severity, 0)


sql_injection_detector = SQLInjectionDetector()