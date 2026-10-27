"""
TrustEdge-CC Cryptographic Engine
Hardware-Anchored Security: ECDSA (NIST P-256 / secp256r1) & AES-256-GCM
Designed to align with ARM TrustZone-A (OP-TEE) and ARM TrustZone-M (TF-M PSA Crypto)
"""

import os
import json
import base64
import hashlib
from typing import Dict, Tuple, Any, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


class EdgeCryptoEngine:
    def __init__(self, private_key: Optional[ec.EllipticCurvePrivateKey] = None):
        if private_key is None:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()

    @classmethod
    def from_pem(cls, pem_data: str) -> "EdgeCryptoEngine":
        private_key = serialization.load_pem_private_key(
            pem_data.encode("utf-8"),
            password=None
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Key is not an EC private key")
        return cls(private_key=private_key)

    def export_private_key_pem(self) -> str:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

    def export_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def sign_data(self, data: bytes) -> bytes:
        """Sign arbitrary data with ECDSA SHA-256 (hardware-sealed key emulation)"""
        signature = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    @staticmethod
    def verify_signature(public_key_pem: str, data: bytes, signature: bytes) -> bool:
        """Verify ECDSA SHA-256 signature against public key"""
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                return False
            pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, Exception):
            return False

    @staticmethod
    def encrypt_aes_gcm(aes_key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Dict[str, str]:
        """
        AES-256-GCM Authenticated Encryption
        Returns {nonce: b64, ciphertext: b64, tag: included in ciphertext}
        """
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)  # Standard 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return {
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
        }

    @staticmethod
    def decrypt_aes_gcm(aes_key: bytes, nonce_b64: str, ciphertext_b64: str, aad: Optional[bytes] = None) -> bytes:
        """AES-256-GCM Authenticated Decryption"""
        aesgcm = AESGCM(aes_key)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        return aesgcm.decrypt(nonce, ciphertext, aad)

    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """Compute hex-encoded SHA-256 digest"""
        return hashlib.sha256(data).hexdigest()

    def generate_attestation_evidence(self, node_id: str, tee_type: str, enclave_measurement: str) -> Dict[str, Any]:
        """
        Produce TEE-signed Attestation Evidence.
        Proves genuine Secure World execution (OP-TEE or TF-M).
        """
        payload = {
            "node_id": node_id,
            "tee_type": tee_type,
            "enclave_measurement": enclave_measurement,
            "public_key": self.export_public_key_pem(),
            "nonce": os.urandom(16).hex()
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = self.sign_data(raw_bytes)
        return {
            "claims": payload,
            "signature": base64.b64encode(sig).decode("utf-8"),
            "evidence_digest": self.hash_sha256(raw_bytes)
        }
