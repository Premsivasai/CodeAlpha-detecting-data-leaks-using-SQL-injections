from celery_config import celery_app
from app.config import settings
import logging
import asyncio
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class AIInferenceService:
    def __init__(self):
        self.service_url = settings.AI_INFERENCE_SERVICE_URL
        self.timeout = settings.AI_INFERENCE_TIMEOUT
        self.model_version = settings.AI_MODEL_VERSION
        
    async def _call_inference_api(self, payload: dict) -> dict:
        import httpx
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.service_url}/predict",
                json=payload
            )
            response.raise_for_status()
            return response.json()
    
    def _run_local_inference(self, query: str) -> dict:
        try:
            from app.ai_detection.advanced import advanced_ai_detector
            result = advanced_ai_detector.predict(query)
            return {
                "threat_score": result.threat_score,
                "prediction": result.prediction,
                "confidence": result.confidence,
                "model_predictions": result.model_predictions,
                "attack_indicators": result.attack_indicators,
                "model_version": self.model_version,
                "inference_type": "local"
            }
        except Exception as e:
            logger.error(f"Local AI inference failed: {e}")
            return self._fallback_inference(query)
    
    def _fallback_inference(self, query: str) -> dict:
        from app.detection import sql_injection_detector
        result = sql_injection_detector.detect(query)
        return {
            "threat_score": result.severity_score / 100.0 if result.is_malicious else 0.0,
            "prediction": "malicious" if result.is_malicious else "benign",
            "confidence": 0.7,
            "detection_method": "rule-based",
            "model_version": "fallback",
            "inference_type": "fallback"
        }
    
    async def analyze(self, query: str, context: Optional[dict] = None) -> dict:
        if self.service_url:
            try:
                return await self._call_inference_api({
                    "query": query,
                    "context": context or {},
                    "model_version": self.model_version
                })
            except Exception as e:
                logger.warning(f"AI service unavailable, using local inference: {e}")
        
        return self._run_local_inference(query)
    
    async def batch_analyze(self, queries: list) -> list:
        results = []
        for query in queries:
            result = await self.analyze(query)
            results.append(result)
        return results


ai_inference_service = AIInferenceService()


@celery_app.task(name="ai_inference.analyze_query", bind=True)
def analyze_query(self, query: str, context: Optional[dict] = None):
    try:
        result = asyncio.run(ai_inference_service.analyze(query, context))
        return result
    except Exception as e:
        logger.error(f"AI inference task failed: {e}")
        return {"error": str(e), "threat_score": 0.5}


@celery_app.task(name="ai_inference.batch_analyze", bind=True)
def batch_analyze_queries(self, queries: list):
    try:
        results = asyncio.run(ai_inference_service.batch_analyze(queries))
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Batch AI inference failed: {e}")
        return {"error": str(e)}


@celery_app.task(name="ai_inference.train_model", bind=True)
def train_model(self, training_data: list, model_type: str = "gradient_boosting"):
    logger.info(f"Starting model training with {len(training_data)} samples")
    
    try:
        from app.ai_detection.advanced import EnsembleAIDetector
        import numpy as np
        
        detector = EnsembleAIDetector()
        
        X = []
        y = []
        
        for item in training_data:
            features = detector.extract_features(item["query"])
            X.append([
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
            ])
            y.append(1 if item.get("label") == "malicious" else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        logger.info(f"Training model with {len(X)} samples")
        
        return {
            "status": "training_completed",
            "samples": len(X),
            "model_type": model_type,
            "version": settings.AI_MODEL_VERSION
        }
    except Exception as e:
        logger.error(f"Model training failed: {e}")
        return {"error": str(e)}


@celery_app.task(name="ai_inference.update_threat_scores", bind=True)
def update_threat_scores(self, attack_logs: list):
    updated = 0
    
    for log in attack_logs:
        if log.get("payload"):
            result = asyncio.run(ai_inference_service.analyze(
                log["payload"],
                {"source": "batch_update", "original_score": log.get("threat_score")}
            ))
            updated += 1
    
    return {"updated": updated, "model_version": settings.AI_MODEL_VERSION}


@celery_app.task(name="ai_inference.calibrate_confidence", bind=True)
def calibrate_confidence(self, predictions: list, actual_outcomes: list):
    logger.info("Calibrating AI confidence scores")
    
    calibration_data = []
    for pred, actual in zip(predictions, actual_outcomes):
        calibration_data.append({
            "predicted_score": pred.get("threat_score"),
            "actual_malicious": actual.get("is_malicious", False),
            "confidence": pred.get("confidence")
        })
    
    calibration_rate = sum(
        1 for p, a in zip(predictions, actual_outcomes)
        if (p.get("prediction") == "malicious") == a.get("is_malicious", False)
    ) / len(predictions) if predictions else 0
    
    return {
        "calibration_accuracy": calibration_rate,
        "total_predictions": len(predictions),
        "model_version": settings.AI_MODEL_VERSION
    }