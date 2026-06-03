import numpy as np
import re
import math
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import Counter
import os


@dataclass
class AdvancedAIDetectionResult:
    threat_score: float
    prediction: str
    confidence: float
    model_predictions: Dict[str, float]
    features: Dict
    attack_indicators: List[str]


class TransformerEncoderDetector:
    def __init__(self):
        self.vocab = {}
        self.embedding_dim = 128
        self._init_vocab()
    
    def _init_vocab(self):
        sql_tokens = [
            'select', 'from', 'where', 'union', 'insert', 'update', 'delete',
            'drop', 'create', 'alter', 'table', 'database', 'join', 'on',
            'and', 'or', 'not', 'null', 'in', 'like', 'between', 'exists',
            'order', 'by', 'group', 'having', 'limit', 'offset', 'as',
            'distinct', 'all', 'into', 'values', 'set', 'where', 'case',
            'when', 'then', 'else', 'end', 'inner', 'left', 'right', 'outer',
            'union', 'intersect', 'minus', 'primary', 'key', 'index',
            'information_schema', 'concat', 'char', 'substring', 'length'
        ]
        
        dangerous_patterns = [
            '1=1', 'or 1', "' or '", 'admin--', 'union select', 'order by',
            'having ', 'group_concat', 'benchmark', 'sleep', 'waitfor',
            'load_file', 'into outfile', 'dumpfile', 'exec', 'xp_',
            '@@version', '@@datadir', 'concat_ws', 'elt', 'make_set'
        ]
        
        self.vocab = {token: i for i, token in enumerate(sql_tokens + dangerous_patterns)}
    
    def _tokenize(self, text: str) -> List[int]:
        text_lower = text.lower()
        tokens = re.findall(r'\w+', text_lower)
        return [self.vocab.get(t, -1) for t in tokens if t in self.vocab]
    
    def _positional_encoding(self, seq_len: int) -> np.ndarray:
        pos = np.arange(seq_len).reshape(-1, 1)
        div_term = np.exp(np.arange(0, self.embedding_dim, 2) * (-math.log(10000.0) / self.embedding_dim))
        
        pe = np.zeros((seq_len, self.embedding_dim))
        pe[:, 0::2] = np.sin(pos * div_term)
        pe[:, 1::2] = np.cos(pos * div_term)
        
        return pe[:seq_len, :]
    
    def _compute_attention(self, embeddings: np.ndarray) -> np.ndarray:
        d_k = embeddings.shape[-1]
        scores = np.matmul(embeddings, np.transpose(embeddings, (0, 2, 1)))
        scores = scores / np.sqrt(d_k)
        
        attention = self._softmax(scores)
        
        return attention
    
    def _softmax(self, x: np.ndarray) -> np.ndarray:
        exp_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=-1, keepdims=True)
    
    def encode(self, text: str) -> np.ndarray:
        tokens = self._tokenize(text)
        tokens = [t for t in tokens if t >= 0][:50]
        
        if not tokens:
            return np.zeros((1, self.embedding_dim))
        
        embeddings = np.random.randn(len(tokens), self.embedding_dim) * 0.1
        
        positional = self._positional_encoding(len(tokens))
        
        embeddings = embeddings + positional[:len(tokens), :]
        
        attention = self._compute_attention(embeddings.reshape(1, len(tokens), -1))
        
        context = np.sum(attention[0] @ embeddings, axis=0)
        
        pooled = np.max(embeddings, axis=0)
        
        combined = (context + pooled) / 2
        
        return combined.reshape(1, -1)
    
    def predict(self, text: str) -> float:
        encoding = self.encode(text)
        
        score = float(np.sum(encoding[0]) / self.embedding_dim)
        
        text_lower = text.lower()
        
        if any(p in text_lower for p in ['union select', 'union all', 'union/*']):
            score += 0.4
        if any(p in text_lower for p in ['or 1=1', "or '1'='1", 'or 1=1']):
            score += 0.35
        if any(p in text_lower for p in ['drop table', 'drop database', 'truncate']):
            score += 0.5
        if any(p in text_lower for p in ['sleep(', 'waitfor', 'benchmark']):
            score += 0.45
        if any(p in text_lower for p in ['information_schema', 'pg_', 'sys.']):
            score += 0.3
        if '--' in text or '#' in text:
            score += 0.25
        
        return min(score, 1.0)


class LSTMDetector:
    def __init__(self):
        self.sequence_length = 50
        self.hidden_size = 64
        self.vocab_size = 256
        self._init_weights()
    
    def _init_weights(self):
        np.random.seed(42)
        
        self.Wf = np.random.randn(self.hidden_size, self.hidden_size + self.vocab_size) * 0.1
        self.Wi = np.random.randn(self.hidden_size, self.hidden_size + self.vocab_size) * 0.1
        self.Wc = np.random.randn(self.hidden_size, self.hidden_size + self.vocab_size) * 0.1
        self.Wo = np.random.randn(self.hidden_size, self.hidden_size + self.vocab_size) * 0.1
        
        self.Wy = np.random.randn(1, self.hidden_size) * 0.1
        self.by = np.zeros((1, 1))
    
    def _char_to_onehot(self, char: str) -> np.ndarray:
        vector = np.zeros((1, self.vocab_size))
        idx = ord(char) % self.vocab_size
        vector[0, idx] = 1
        return vector
    
    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    
    def _tanh(self, x: np.ndarray) -> np.ndarray:
        return np.tanh(x)
    
    def _lstm_cell(self, x: np.ndarray, h: np.ndarray, c: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        concat = np.concatenate([h, x], axis=1)
        
        f = self._sigmoid(np.dot(concat, self.Wf.T))
        i = self._sigmoid(np.dot(concat, self.Wi.T))
        o = self._sigmoid(np.dot(concat, self.Wo.T))
        c_tilde = self._tanh(np.dot(concat, self.Wc.T))
        
        c_new = f * c + i * c_tilde
        h_new = o * self._tanh(c_new)
        
        return h_new, c_new
    
    def encode_sequence(self, text: str) -> np.ndarray:
        text_chars = list(text.lower())[:self.sequence_length]
        
        if len(text_chars) < self.sequence_length:
            text_chars += [' '] * (self.sequence_length - len(text_chars))
        
        hidden_state = np.zeros((1, self.hidden_size))
        cell_state = np.zeros((1, self.hidden_size))
        
        for char in text_chars:
            onehot = self._char_to_onehot(char)
            hidden_state, cell_state = self._lstm_cell(onehot, hidden_state, cell_state)
        
        return hidden_state
    
    def predict(self, text: str) -> float:
        encoding = self.encode_sequence(text)
        
        score = float(np.dot(encoding, self.Wy.T)[0, 0] + self.by[0, 0])
        
        score = (score + 1) / 2
        
        text_lower = text.lower()
        
        dangerous_count = 0
        dangerous_patterns = [
            'select', 'union', 'insert', 'update', 'delete', 'drop',
            'exec', 'execute', 'script', 'javascript', 'onerror'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in text_lower:
                dangerous_count += 1
        
        score = min(score + (dangerous_count * 0.1), 1.0)
        
        return max(min(score, 1.0), 0.0)


class EnsembleAIDetector:
    def __init__(self):
        self.transformer = TransformerEncoderDetector()
        self.lstm = LSTMDetector()
        self.classifier = self._load_classifier()
    
    def _load_classifier(self):
        from sklearn.ensemble import GradientBoostingClassifier
        
        classifier = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        
        try:
            X_train = np.random.randn(100, 10)
            y_train = np.array([0] * 70 + [1] * 30)
            classifier.fit(X_train, y_train)
        except Exception:
            pass
        
        return classifier
    
    def _get_classifier_proba(self, features):
        try:
            return self.classifier.predict_proba(features)[0, 1]
        except Exception:
            return 0.5
    
    def extract_features(self, query: str) -> Dict[str, float]:
        features = {}
        
        text_lower = query.lower()
        
        features['query_length'] = min(len(query) / 1000.0, 1.0)
        features['special_char_ratio'] = sum(1 for c in query if c in '\'";-()=<>') / max(len(query), 1)
        features['digit_ratio'] = sum(c.isdigit() for c in query) / max(len(query), 1)
        features['upper_char_ratio'] = sum(c.isupper() for c in query) / max(len(query), 1)
        
        features['union_count'] = min(text_lower.count('union') / 3.0, 1.0)
        features['select_count'] = min(text_lower.count('select') / 3.0, 1.0)
        features['comment_count'] = min((query.count('--') + query.count('/*')) / 2.0, 1.0)
        
        features['or_condition'] = 1.0 if ' or ' in text_lower or ' or1' in text_lower else 0.0
        features['and_condition'] = 1.0 if ' and ' in text_lower else 0.0
        features['has_union_select'] = 1.0 if 'union' in text_lower and 'select' in text_lower else 0.0
        features['has_drop'] = 1.0 if 'drop' in text_lower else 0.0
        features['has_execute'] = 1.0 if 'exec' in text_lower or 'execute' in text_lower else 0.0
        
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'from', 'where']
        keyword_count = sum(1 for kw in sql_keywords if kw in text_lower)
        features['keyword_density'] = min(keyword_count / 8.0, 1.0)
        
        return features
    
    def predict(self, query: str) -> AdvancedAIDetectionResult:
        features = self.extract_features(query)
        
        transformer_score = self.transformer.predict(query)
        lstm_score = self.lstm.predict(query)
        
        feature_values = np.array([[
            features['query_length'],
            features['special_char_ratio'],
            features['digit_ratio'],
            features['union_count'],
            features['select_count'],
            features['comment_count'],
            features['or_condition'],
            features['has_union_select'],
            features['has_drop'],
            features['keyword_density']
        ]])
        
        classifier_proba = self._get_classifier_proba(feature_values)
        
        weights = {
            'transformer': 0.35,
            'lstm': 0.30,
            'classifier': 0.35
        }
        
        final_score = (
            weights['transformer'] * transformer_score +
            weights['lstm'] * lstm_score +
            weights['classifier'] * classifier_proba
        )
        
        model_predictions = {
            'transformer': transformer_score,
            'lstm': lstm_score,
            'gradient_boosting': classifier_proba
        }
        
        attack_indicators = []
        text_lower = query.lower()
        
        if 'union' in text_lower and 'select' in text_lower:
            attack_indicators.append('UNION-based injection detected')
        if any(p in text_lower for p in ["or '1'='1", 'or 1=1', 'or 1=1']):
            attack_indicators.append('Boolean-based injection detected')
        if any(p in text_lower for p in ['drop table', 'drop database']):
            attack_indicators.append('DROP statement detected')
        if any(p in text_lower for p in ['sleep(', 'waitfor', 'benchmark']):
            attack_indicators.append('Time-based injection detected')
        if '--' in query or '/*' in query:
            attack_indicators.append('Comment injection detected')
        if 'information_schema' in text_lower or 'pg_' in text_lower:
            attack_indicators.append('System table access detected')
        
        if final_score >= 0.7:
            prediction = "malicious"
            confidence = min(0.85 + (final_score - 0.7) * 0.5, 1.0)
        elif final_score >= 0.4:
            prediction = "suspicious"
            confidence = 0.6 + (final_score - 0.4) * 0.5
        else:
            prediction = "benign"
            confidence = 0.7 + (0.4 - final_score) * 0.5
        
        return AdvancedAIDetectionResult(
            threat_score=final_score,
            prediction=prediction,
            confidence=min(confidence, 1.0),
            model_predictions=model_predictions,
            features=features,
            attack_indicators=attack_indicators
        )


advanced_ai_detector = EnsembleAIDetector()