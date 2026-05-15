from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import hashlib
import base64
import json
from typing import Union, Optional
from app.config import settings


class AES256Encryption:
    def __init__(self, key: Optional[str] = None):
        self.key = key or settings.ENCRYPTION_KEY
        self._key_bytes = self._derive_key(self.key)

    def _derive_key(self, password: str) -> bytes:
        return PBKDF2(
            password,
            b'secure_shield_salt',
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA256
        )

    def _generate_nonce(self) -> bytes:
        return get_random_bytes(16)

    def encrypt(self, plaintext: Union[str, dict, list]) -> str:
        if isinstance(plaintext, (dict, list)):
            plaintext = json.dumps(plaintext)
        
        nonce = self._generate_nonce()
        cipher = AES.new(self._key_bytes, AES.MODE_EAX, nonce=nonce)
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        result = {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
        
        return base64.b64encode(json.dumps(result).encode('utf-8')).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        try:
            encrypted_json = json.loads(base64.b64decode(encrypted_data.encode('utf-8')).decode('utf-8'))
            
            nonce = base64.b64decode(encrypted_json['nonce'])
            ciphertext = base64.b64decode(encrypted_json['ciphertext'])
            tag = base64.b64decode(encrypted_json['tag'])
            
            cipher = AES.new(self._key_bytes, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def encrypt_dict(self, data: dict, fields_to_encrypt: list) -> dict:
        result = data.copy()
        for field in fields_to_encrypt:
            if field in result and result[field]:
                result[field] = self.encrypt(str(result[field]))
        return result

    def decrypt_dict(self, data: dict, fields_to_decrypt: list) -> dict:
        result = data.copy()
        for field in fields_to_decrypt:
            if field in result and result[field]:
                try:
                    result[field] = self.decrypt(result[field])
                except:
                    pass
        return result

    def hash_password(self, password: str) -> str:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            b'secure_shield_password_salt',
            100000
        ).hex()

    def verify_password(self, password: str, hashed: str) -> bool:
        return self.hash_password(password) == hashed

    def generate_token(self, length: int = 32) -> str:
        return base64.b64encode(get_random_bytes(length)).decode('utf-8').replace('+', '').replace('/', '').replace('=', '')


encryption_service = AES256Encryption()


class KeyManager:
    def __init__(self):
        self._master_key = settings.ENCRYPTION_KEY
        self._rotation_counter = 0

    def rotate_key(self) -> str:
        self._rotation_counter += 1
        new_key = f"{self._master_key}_{self._rotation_counter}"
        return hashlib.sha256(new_key.encode()).hexdigest()

    def get_current_key(self) -> str:
        return self._master_key


key_manager = KeyManager()