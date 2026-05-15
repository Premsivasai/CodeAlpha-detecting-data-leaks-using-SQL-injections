import pytest
from app.detection import sql_injection_detector, Severity


class TestSQLInjectionDetector:
    def test_union_based_attack(self):
        query = "SELECT * FROM users UNION SELECT password FROM admins"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is True
        assert result.attack_type.value == "union_based"

    def test_boolean_based_attack(self):
        query = "SELECT * FROM users WHERE id = 1 OR 1=1"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is True
        assert result.attack_type.value == "tautology"

    def test_time_based_attack(self):
        query = "SELECT * FROM users WHERE id = 1 AND SLEEP(5)"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is True

    def test_comment_injection(self):
        query = "SELECT * FROM users WHERE id = 1--"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is True

    def test_normal_query(self):
        query = "SELECT id, name, email FROM users WHERE id = 1"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is False

    def test_parameterized_query(self):
        query = "SELECT * FROM products WHERE category = ?"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is False

    def test_error_based_detection(self):
        query = "SELECT * FROM users WHERE id = 1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is True

    def test_stacked_query(self):
        query = "SELECT * FROM users; DROP TABLE users;"
        result = sql_injection_detector.detect(query)
        assert result.is_malicious is True


class TestAIQueryDetector:
    def test_malicious_query_detection(self):
        from app.ai_detection import ai_detector
        query = "admin' OR '1'='1"
        result = ai_detector.predict(query)
        assert result.threat_score > 0.3
        assert result.prediction in ["malicious", "suspicious"]

    def test_benign_query(self):
        from app.ai_detection import ai_detector
        query = "SELECT name, email FROM customers WHERE status = 'active'"
        result = ai_detector.predict(query)
        assert result.threat_score < 0.5

    def test_feature_extraction(self):
        from app.ai_detection import ai_detector
        features = ai_detector.extract_features("SELECT * FROM users")
        assert 'keyword_density' in features
        assert 'special_char_ratio' in features
        assert 'entropy' in features


class TestEncryption:
    def test_encrypt_decrypt(self):
        from app.encryption import encryption_service
        plaintext = "sensitive data"
        encrypted = encryption_service.encrypt(plaintext)
        decrypted = encryption_service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_dict_encryption(self):
        from app.encryption import encryption_service
        data = {"email": "test@example.com", "password": "secret"}
        encrypted = encryption_service.encrypt_dict(data, ["email", "password"])
        assert encrypted["email"] != data["email"]

    def test_password_hashing(self):
        from app.encryption import encryption_service
        password = "secure_password"
        hashed = encryption_service.hash_password(password)
        assert hashed != password
        assert encryption_service.verify_password(password, hashed) is True


class TestCapabilityManager:
    def test_generate_capability(self):
        from app.capability import capability_manager
        from datetime import datetime, timedelta
        
        token = capability_manager.generate_capability(
            user_id=1,
            username="testuser",
            permissions=["read:own", "write:own"],
            resources=["profile"],
            expiration_days=7
        )
        assert token is not None
        assert len(token) > 0

    def test_validate_capability(self):
        from app.capability import capability_manager
        from datetime import datetime, timedelta
        
        token = capability_manager.generate_capability(
            user_id=1,
            username="testuser",
            permissions=["read:own"],
            resources=["profile"],
            expiration_days=7
        )
        
        is_valid, capability, message = capability_manager.validate_capability(
            token,
            required_permission="read:own",
            required_resource="profile"
        )
        assert is_valid is True
        assert capability is not None


class TestAuthService:
    def test_create_tokens(self):
        from app.auth import auth_service
        from app.models import User, UserRole
        from datetime import datetime
        
        user = User(
            id=1,
            username="testuser",
            hashed_password="hashed",
            role=UserRole.USER,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        tokens = auth_service.create_tokens(user)
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert tokens["token_type"] == "bearer"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])