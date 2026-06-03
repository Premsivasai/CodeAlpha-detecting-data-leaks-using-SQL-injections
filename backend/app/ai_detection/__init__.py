import re
import math
import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import Counter
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer


@dataclass
class AIDetectionResult:
    threat_score: float
    prediction: str
    confidence: float
    features: Dict


class AIQueryDetector:
    def __init__(self, model_path: str = None):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        self._init_builtin_model()
    
    def _init_builtin_model(self):
        self.feature_weights = {
            'keyword_density': 0.15,
            'special_char_ratio': 0.12,
            'query_length': 0.08,
            'entropy': 0.10,
            'union_count': 0.15,
            'comment_detection': 0.08,
            'parenthesis_depth': 0.07,
            'numeric_literal_count': 0.10,
            'quote_count': 0.10,
            'encoded_chars': 0.05,
        }
        
        self.known_malicious_patterns = [
            "union select",
            "or 1=1",
            "' or '1'='1",
            "'; drop table",
            "1; delete from",
            "union all select",
            "and exists",
            "waitfor delay",
            "benchmark(",
            "sleep(",
            "load_file(",
            "into outfile",
            "information_schema",
            "@@version",
            "0x",
            "char(",
            "concat(",
            "extractvalue(",
            "updatexml(",
        ]
        
        self.is_trained = True

    def extract_features(self, query: str) -> Dict[str, float]:
        features = {}
        
        words = query.lower().split()
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 
                       'alter', 'union', 'from', 'where', 'join', 'having', 'group']
        keyword_count = sum(1 for w in words if w in sql_keywords)
        total_words = max(len(words), 1)
        features['keyword_density'] = keyword_count / total_words
        
        special_chars = sum(1 for c in query if c in "'\";,-/*+()=<>")
        features['special_char_ratio'] = special_chars / max(len(query), 1)
        
        features['query_length'] = min(len(query) / 1000.0, 1.0)
        
        features['entropy'] = self._calculate_entropy(query)
        
        features['union_count'] = min(query.lower().count('union') / 3.0, 1.0)
        
        comment_patterns = ['--', '#', '/*', '*/']
        features['comment_detection'] = sum(1 for p in comment_patterns if p in query) / len(comment_patterns)
        
        features['parenthesis_depth'] = min(
            max(query.count('('), query.count(')')) / 10.0, 1.0
        )
        
        numeric_literals = len(re.findall(r'\b\d+\b', query))
        features['numeric_literal_count'] = min(numeric_literals / 10.0, 1.0)
        
        features['quote_count'] = min(
            (query.count("'") + query.count('"')) / max(len(query), 1) * 10, 1.0
        )
        
        encoded_chars = query.count('%')
        features['encoded_chars'] = min(encoded_chars / 5.0, 1.0)
        
        return features

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return min(entropy / 5.0, 1.0)

    def _calculate_threat_score(self, features: Dict) -> float:
        score = 0.0
        
        for feature_name, value in features.items():
            # Only include numeric features in score calculation
            weight = self.feature_weights.get(feature_name, 0.1)
            if isinstance(value, (int, float)):
                score += weight * value
            else:
                # skip non-numeric (e.g., 'query')
                continue
        
        pattern_score = 0.0
        query_lower = features.get('query', '').lower() if isinstance(features.get('query'), str) else ''
        
        for pattern in self.known_malicious_patterns:
            if pattern in query_lower:
                pattern_score += 0.10
        
        score = min(score + pattern_score, 1.0)
        
        return score

    def predict(self, query: str) -> AIDetectionResult:
        features = self.extract_features(query)
        features['query'] = query
        
        threat_score = self._calculate_threat_score(features)
        
        if threat_score >= 0.7:
            prediction = "malicious"
            confidence = 0.85 + (threat_score - 0.7) * 0.5
        elif threat_score >= 0.3:
            prediction = "suspicious"
            confidence = 0.6 + (threat_score - 0.3) * 0.5
        else:
            prediction = "benign"
            confidence = 0.7 + (0.4 - threat_score) * 0.5
        
        return AIDetectionResult(
            threat_score=threat_score,
            prediction=prediction,
            confidence=min(confidence, 1.0),
            features=features
        )

    def save_model(self, path: str):
        model_data = {
            'feature_weights': self.feature_weights,
            'known_malicious_patterns': self.known_malicious_patterns,
        }
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, path: str):
        if os.path.exists(path):
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
                self.feature_weights = model_data.get('feature_weights', self.feature_weights)
                self.known_malicious_patterns = model_data.get('known_malicious_patterns', self.known_malicious_patterns)


class MLPayloadClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 3))
        self.classifier = RandomForestClassifier(n_estimators=100, max_depth=20)
        self.is_trained = False
        # Attempt to load a persisted model artifact if available
        from app.config import settings
        try:
            self.load_model(settings.AI_MODEL_PATH)
        except Exception:
            # model not available at init; remain untrained until explicit training
            self.is_trained = False
    
    def prepare_dataset(self) -> Tuple[List[str], List[int]]:
        benign_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, email FROM customers WHERE status = 'active'",
            "INSERT INTO orders (product_id, quantity) VALUES (5, 2)",
            "UPDATE products SET price = 99.99 WHERE id = 3",
            "DELETE FROM cart WHERE user_id = 10",
            "SELECT COUNT(*) FROM users WHERE active = 1",
            "SELECT * FROM posts ORDER BY created_at DESC LIMIT 10",
            "SELECT u.*, p.* FROM users u JOIN profiles p ON u.id = p.user_id",
        ]
        
        malicious_queries = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
            "SELECT id, name FROM users UNION SELECT password, email FROM admins",
            "'; DROP TABLE users; --",
            "SELECT * FROM products WHERE id = 1; DELETE FROM cart;",
            "SELECT * FROM users WHERE id = 1 AND (SELECT COUNT(*) FROM users) > 0",
            "admin'--",
            "SELECT * FROM users WHERE id = 1' OR '1'='1' --",
            "UNION SELECT NULL, NULL, NULL--",
            "1' AND '1'='1",
            "'; WAITFOR DELAY '00:00:05'--",
            "SELECT * FROM users WHERE id = (SELECT MAX(id) FROM users)",
            "' OR 1=1--",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL, version()--",
        ]
        
        queries = benign_queries + malicious_queries
        labels = [0] * len(benign_queries) + [1] * len(malicious_queries)
        
        return queries, labels
    
    def train(self, queries: List[str], labels: List[int]):
        X = self.vectorizer.fit_transform(queries)
        self.classifier.fit(X, labels)
        self.is_trained = True
        try:
            from app.config import settings
            self.save_model(settings.AI_MODEL_PATH)
        except Exception:
            pass
    
    def predict(self, query: str) -> Tuple[str, float]:
        if not self.is_trained:
            # If model isn't trained or loaded, return benign with low confidence
            return "benign", 0.5

        X = self.vectorizer.transform([query])
        prediction = self.classifier.predict(X)[0]
        probability = self.classifier.predict_proba(X)[0]

        return "malicious" if prediction == 1 else "benign", float(max(probability))

    def save_model(self, path: str):
        import pickle
        model_data = {
            'vectorizer': self.vectorizer,
            'classifier': self.classifier,
        }
        dirpath = os.path.dirname(path)
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, path: str):
        import pickle
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
            self.vectorizer = model_data.get('vectorizer', self.vectorizer)
            self.classifier = model_data.get('classifier', self.classifier)
            self.is_trained = True


ai_detector = AIQueryDetector()
ml_classifier = MLPayloadClassifier()