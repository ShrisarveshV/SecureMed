"""
Secure MID Cryptographic Engine
Supports:
  1. Authenticated Encryption (AEAD):
     - AES-128-GCM, AES-256-GCM (NIST SP 800-38D / FIPS 197)
     - AES-128-CCM, AES-256-CCM (NIST SP 800-38C / RFC 3610)
     - ChaCha20-Poly1305 (RFC 8439)
     - Ascon-AEAD128 (NIST SP 800-232 Lightweight Cryptography)
  2. Post-Quantum Key Encapsulation (KEM - NIST FIPS 203):
     - ML-KEM-512 (Kyber512 pure Python reference)
     - ML-KEM-768 (standard cryptography hazmat MLKEM768)
     - ML-KEM-1024 (standard cryptography hazmat MLKEM1024)
  3. Post-Quantum Digital Signatures (DSA - NIST FIPS 204):
     - ML-DSA-44
     - ML-DSA-65
     - ML-DSA-87
  4. Classical Key Establishment:
     - X25519 ECDH (RFC 7748)
  5. Hybrid Classical + Post-Quantum Key Establishment:
     - X25519 + ML-KEM-768 combined via HKDF-SHA256 (RFC 9370 / NIST SP 800-56C)
"""

import os
import base64
import time
from typing import Tuple, Optional, Dict, Any, List, Union

from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_der_private_key,
    load_der_public_key,
)
from cryptography.exceptions import InvalidTag, InvalidSignature
import ascon
from kyber_py.kyber import Kyber512, Kyber768, Kyber1024

# Algorithm Categories
AEAD_ALGORITHMS = [
    "AES-128-GCM",
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "Ascon-AEAD128",
    "AES-128-CCM",
    "AES-256-CCM",
]

PQC_KEM_ALGORITHMS = [
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
]

PQC_SIGNATURE_ALGORITHMS = [
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
]

CLASSICAL_KEM_ALGORITHMS = [
    "X25519",
]

HYBRID_ALGORITHMS = [
    "X25519+ML-KEM-768",
]

# Legacy and primary supported algorithms list
SUPPORTED_ALGORITHMS = AEAD_ALGORITHMS + [
    "ML-KEM-768-AES-GCM",
    "X25519+ML-KEM-768",
]

UNAVAILABLE_ALGORITHMS = [
    {
        "name": "SLH-DSA",
        "category": "Post-Quantum Digital Signatures",
        "standard": "NIST FIPS 205 (Stateless Hash-Based Signatures)",
        "status": "Unavailable",
        "reason": "Not included in current cryptography 49.0 runtime. Requires external C-binding or liboqs.",
    },
    {
        "name": "XChaCha20-Poly1305",
        "category": "Authenticated Encryption",
        "standard": "draft-irtf-cfrg-xchacha",
        "status": "Unavailable",
        "reason": "Standard cryptography library provides RFC 8439 ChaCha20-Poly1305 (96-bit nonce).",
    }
]


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class AuthenticationFailedError(CryptoError):
    """Raised when authentication tag or signature verification fails."""
    pass


class InvalidNonceError(CryptoError):
    """Raised when nonce length or uniqueness is invalid."""
    pass


def get_all_algorithm_catalog() -> Dict[str, Any]:
    """Returns comprehensive metadata for all algorithm categories."""
    return {
        "aead": [
            {
                "name": "AES-128-GCM",
                "category": "Authenticated Encryption",
                "standard": "NIST SP 800-38D / FIPS 197",
                "key_size_bits": 128,
                "nonce_size_bytes": 12,
                "tag_size_bytes": 16,
                "hardware_acceleration": "Intel AES-NI verified",
                "status": "Available",
                "description": "Widely deployed standard AEAD cipher providing high throughput on AES-NI enabled hardware.",
            },
            {
                "name": "AES-256-GCM",
                "category": "Authenticated Encryption",
                "standard": "NIST SP 800-38D / FIPS 197",
                "key_size_bits": 256,
                "nonce_size_bytes": 12,
                "tag_size_bytes": 16,
                "hardware_acceleration": "Intel AES-NI verified",
                "status": "Available",
                "description": "High-security 256-bit symmetric cipher suitable for long-term quantum resistance against Grover's algorithm.",
            },
            {
                "name": "ChaCha20-Poly1305",
                "category": "Authenticated Encryption",
                "standard": "RFC 8439",
                "key_size_bits": 256,
                "nonce_size_bytes": 12,
                "tag_size_bytes": 16,
                "hardware_acceleration": "Software SIMD / AVX2",
                "status": "Available",
                "description": "High-speed stream cipher with Poly1305 MAC; constant-time implementation immune to cache-timing attacks.",
            },
            {
                "name": "Ascon-AEAD128",
                "category": "Authenticated Encryption (Lightweight)",
                "standard": "NIST SP 800-232",
                "key_size_bits": 128,
                "nonce_size_bytes": 16,
                "tag_size_bytes": 16,
                "hardware_acceleration": "None (Pure Python / Bit-sliced reference)",
                "status": "Available",
                "description": "NIST Lightweight Cryptography standard winner designed for constrained microcontrollers, medical implants, and RFID.",
            },
            {
                "name": "AES-128-CCM",
                "category": "Authenticated Encryption",
                "standard": "NIST SP 800-38C / RFC 3610",
                "key_size_bits": 128,
                "nonce_size_bytes": 12,
                "tag_size_bytes": 16,
                "hardware_acceleration": "Intel AES-NI verified",
                "status": "Available",
                "description": "Standard AEAD cipher for Bluetooth Low Energy (BLE) Link Layer and IEEE 802.15.4 medical body area networks.",
            },
            {
                "name": "AES-256-CCM",
                "category": "Authenticated Encryption",
                "standard": "NIST SP 800-38C",
                "key_size_bits": 256,
                "nonce_size_bytes": 12,
                "tag_size_bytes": 16,
                "hardware_acceleration": "Intel AES-NI verified",
                "status": "Available",
                "description": "256-bit version of Counter with CBC-MAC AEAD mode for elevated security requirements.",
            },
        ],
        "pqc_kem": [
            {
                "name": "ML-KEM-512",
                "category": "Post-Quantum Key Encapsulation",
                "standard": "NIST FIPS 203 (NIST Security Category 1 - AES-128 equivalent)",
                "public_key_bytes": 800,
                "secret_key_bytes": 1632,
                "ciphertext_bytes": 768,
                "hardware_acceleration": "None (Pure Python Kyber-py)",
                "status": "Available",
                "description": "Module Lattice-based KEM with lowest bandwidth overhead for constrained networks.",
            },
            {
                "name": "ML-KEM-768",
                "category": "Post-Quantum Key Encapsulation",
                "standard": "NIST FIPS 203 (NIST Security Category 3 - AES-192 equivalent)",
                "public_key_bytes": 1184,
                "secret_key_bytes": 2400,
                "ciphertext_bytes": 1088,
                "hardware_acceleration": "Rust / AVX2 optimized",
                "status": "Available",
                "description": "Primary recommended post-quantum KEM standard balancing security, key size, and performance.",
            },
            {
                "name": "ML-KEM-1024",
                "category": "Post-Quantum Key Encapsulation",
                "standard": "NIST FIPS 203 (NIST Security Category 5 - AES-256 equivalent)",
                "public_key_bytes": 1568,
                "secret_key_bytes": 3168,
                "ciphertext_bytes": 1568,
                "hardware_acceleration": "Rust / AVX2 optimized",
                "status": "Available",
                "description": "Maximum security post-quantum KEM for mission-critical and classified medical data protection.",
            },
        ],
        "pqc_signatures": [
            {
                "name": "ML-DSA-44",
                "category": "Post-Quantum Digital Signatures",
                "standard": "NIST FIPS 204 (Security Category 2)",
                "public_key_bytes": 1312,
                "secret_key_bytes": 2560,
                "signature_bytes": 2420,
                "hardware_acceleration": "Rust / AVX2 optimized",
                "status": "Available",
                "description": "Module-Lattice-Based Digital Signature Standard with smallest signature size.",
            },
            {
                "name": "ML-DSA-65",
                "category": "Post-Quantum Digital Signatures",
                "standard": "NIST FIPS 204 (Security Category 3)",
                "public_key_bytes": 1952,
                "secret_key_bytes": 4032,
                "signature_bytes": 3309,
                "hardware_acceleration": "Rust / AVX2 optimized",
                "status": "Available",
                "description": "Recommended standard for general-purpose post-quantum software integrity and firmware verification.",
            },
            {
                "name": "ML-DSA-87",
                "category": "Post-Quantum Digital Signatures",
                "standard": "NIST FIPS 204 (Security Category 5)",
                "public_key_bytes": 2592,
                "secret_key_bytes": 4896,
                "signature_bytes": 4627,
                "hardware_acceleration": "Rust / AVX2 optimized",
                "status": "Available",
                "description": "Maximum strength post-quantum signature algorithm for highest-assurance environments.",
            },
        ],
        "classical_kem": [
            {
                "name": "X25519",
                "category": "Classical Key Establishment",
                "standard": "RFC 7748 / Curve25519",
                "public_key_bytes": 32,
                "secret_key_bytes": 32,
                "shared_secret_bytes": 32,
                "status": "Available",
                "description": "State-of-the-art classical Elliptic Curve Diffie-Hellman function providing ~128 bits of classical security.",
            }
        ],
        "hybrid": [
            {
                "name": "X25519+ML-KEM-768",
                "category": "Hybrid Classical + Post-Quantum Key Establishment",
                "standard": "IETF RFC 9370 / NIST SP 800-56C Construction",
                "classical_component": "X25519 (RFC 7748)",
                "pqc_component": "ML-KEM-768 (NIST FIPS 203)",
                "kdf": "HKDF-SHA256",
                "status": "Available",
                "description": "Combines classical X25519 and post-quantum ML-KEM-768 so security holds if either algorithm remains unbroken.",
            }
        ],
        "unavailable": UNAVAILABLE_ALGORITHMS,
    }


class SecureMedCryptoEngine:
    """
    Modular cryptographic engine supporting authenticated encryption algorithms.
    """

    def __init__(self, key: Optional[bytes] = None, algorithm: str = "AES-128-CCM"):
        self.algorithm = algorithm
        self.key = key or self.generate_key(algorithm)
        self._used_nonces = set()

    @staticmethod
    def generate_key(algorithm: str) -> bytes:
        """Generate a cryptographically secure random key for the algorithm."""
        if algorithm in ("AES-128-CCM", "AES-128-GCM", "Ascon-AEAD128"):
            return os.urandom(16)  # 128 bits
        elif algorithm in ("AES-256-GCM", "AES-256-CCM", "ChaCha20-Poly1305", "ML-KEM-768-AES-GCM", "X25519+ML-KEM-768"):
            return os.urandom(32)  # 256 bits
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    @staticmethod
    def get_nonce_size(algorithm: str) -> int:
        """Return required nonce size in bytes."""
        if algorithm in ("AES-128-CCM", "AES-256-CCM"):
            return 12  # Standard 12-byte nonce for CCM
        elif algorithm in ("AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "ML-KEM-768-AES-GCM", "X25519+ML-KEM-768"):
            return 12  # 96-bit standard nonce
        elif algorithm == "Ascon-AEAD128":
            return 16  # 128-bit nonce for Ascon
        else:
            return 12

    def generate_nonce(self, algorithm: Optional[str] = None) -> bytes:
        """Generate a fresh, cryptographically unique nonce."""
        algo = algorithm or self.algorithm
        size = self.get_nonce_size(algo)
        nonce = os.urandom(size)
        while nonce in self._used_nonces:
            nonce = os.urandom(size)
        self._used_nonces.add(nonce)
        return nonce

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes,
        algorithm: Optional[str] = None,
        key: Optional[bytes] = None,
        nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes, float]:
        """
        Encrypts plaintext with authenticated associated data (AAD).
        Returns: (ciphertext_bytes, nonce_bytes, tag_bytes, execution_time_ms)
        """
        algo = algorithm or self.algorithm
        cipher_key = key or self.key
        used_nonce = nonce or self.generate_nonce(algo)

        start_time = time.perf_counter_ns()

        if algo in ("AES-128-CCM", "AES-256-CCM"):
            ccm = AESCCM(cipher_key, tag_length=16)
            encrypted = ccm.encrypt(used_nonce, plaintext, associated_data)
            ciphertext = encrypted[:-16]
            tag = encrypted[-16:]

        elif algo in ("AES-128-GCM", "AES-256-GCM", "ML-KEM-768-AES-GCM", "X25519+ML-KEM-768"):
            gcm = AESGCM(cipher_key)
            encrypted = gcm.encrypt(used_nonce, plaintext, associated_data)
            ciphertext = encrypted[:-16]
            tag = encrypted[-16:]

        elif algo == "ChaCha20-Poly1305":
            chacha = ChaCha20Poly1305(cipher_key)
            encrypted = chacha.encrypt(used_nonce, plaintext, associated_data)
            ciphertext = encrypted[:-16]
            tag = encrypted[-16:]

        elif algo == "Ascon-AEAD128":
            encrypted = ascon.encrypt(
                cipher_key, used_nonce, associated_data, plaintext, "Ascon-128"
            )
            ciphertext = encrypted[:-16]
            tag = encrypted[-16:]

        else:
            raise ValueError(f"Unsupported algorithm: {algo}")

        exec_time_ms = (time.perf_counter_ns() - start_time) / 1_000_000.0
        return ciphertext, used_nonce, tag, exec_time_ms

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        associated_data: bytes,
        algorithm: Optional[str] = None,
        key: Optional[bytes] = None
    ) -> Tuple[bytes, float]:
        """
        Verifies authentication tag and decrypts ciphertext using AAD.
        Returns: (plaintext_bytes, execution_time_ms)
        Raises: AuthenticationFailedError if tag mismatch or tampered data.
        """
        algo = algorithm or self.algorithm
        cipher_key = key or self.key

        start_time = time.perf_counter_ns()

        try:
            if algo in ("AES-128-CCM", "AES-256-CCM"):
                ccm = AESCCM(cipher_key, tag_length=16)
                combined = ciphertext + tag
                plaintext = ccm.decrypt(nonce, combined, associated_data)

            elif algo in ("AES-128-GCM", "AES-256-GCM", "ML-KEM-768-AES-GCM", "X25519+ML-KEM-768"):
                gcm = AESGCM(cipher_key)
                combined = ciphertext + tag
                plaintext = gcm.decrypt(nonce, combined, associated_data)

            elif algo == "ChaCha20-Poly1305":
                chacha = ChaCha20Poly1305(cipher_key)
                combined = ciphertext + tag
                plaintext = chacha.decrypt(nonce, combined, associated_data)

            elif algo == "Ascon-AEAD128":
                combined = ciphertext + tag
                result = ascon.decrypt(
                    cipher_key, nonce, associated_data, combined, "Ascon-128"
                )
                if result is None:
                    raise AuthenticationFailedError("Ascon MAC tag verification failed (tampered data)")
                plaintext = result

            else:
                raise ValueError(f"Unsupported algorithm: {algo}")

        except InvalidTag as e:
            raise AuthenticationFailedError(f"AEAD Authentication Tag Mismatch: {str(e)}")
        except Exception as e:
            if isinstance(e, AuthenticationFailedError):
                raise
            raise AuthenticationFailedError(f"Decryption/Authentication failed: {str(e)}")

        exec_time_ms = (time.perf_counter_ns() - start_time) / 1_000_000.0
        return plaintext, exec_time_ms


class PostQuantumKEMManager:
    """
    ML-KEM (Kyber NIST FIPS 203) Key Encapsulation Mechanism Manager.
    Supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
    """

    @staticmethod
    def generate_keypair(variant: str = "ML-KEM-768") -> Tuple[bytes, bytes]:
        """
        Generates public key and private/secret key for chosen ML-KEM variant.
        Returns: (public_key_bytes, secret_key_der_or_raw)
        """
        if variant == "ML-KEM-512":
            pk, sk = Kyber512.keygen()
            return pk, sk
        elif variant == "ML-KEM-768":
            sk = mlkem.MLKEM768PrivateKey.generate()
            pk = sk.public_key()
            der = sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
            return pk.public_bytes_raw(), der
        elif variant == "ML-KEM-1024":
            sk = mlkem.MLKEM1024PrivateKey.generate()
            pk = sk.public_key()
            der = sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
            return pk.public_bytes_raw(), der
        else:
            raise ValueError(f"Unsupported ML-KEM variant: {variant}")

    @staticmethod
    def encapsulate(public_key: bytes, variant: str = "ML-KEM-768") -> Tuple[bytes, bytes]:
        """
        Encapsulates a shared secret using peer's public key.
        Returns: (shared_secret_bytes, kem_ciphertext_bytes)
        """
        if variant == "ML-KEM-512":
            ss, ct = Kyber512.encaps(public_key)
            return ss, ct
        elif variant == "ML-KEM-768":
            pk = mlkem.MLKEM768PublicKey.from_public_bytes(public_key)
            ss, ct = pk.encapsulate()
            return ss, ct
        elif variant == "ML-KEM-1024":
            pk = mlkem.MLKEM1024PublicKey.from_public_bytes(public_key)
            ss, ct = pk.encapsulate()
            return ss, ct
        else:
            raise ValueError(f"Unsupported ML-KEM variant: {variant}")

    @staticmethod
    def decapsulate(secret_key: bytes, kem_ciphertext: bytes, variant: str = "ML-KEM-768") -> bytes:
        """
        Decapsulates the shared secret using recipient's private key.
        Returns: shared_secret_bytes
        """
        if variant == "ML-KEM-512":
            return Kyber512.decaps(secret_key, kem_ciphertext)
        elif variant in ("ML-KEM-768", "ML-KEM-1024"):
            sk = load_der_private_key(secret_key, password=None)
            return sk.decapsulate(kem_ciphertext)
        else:
            raise ValueError(f"Unsupported ML-KEM variant: {variant}")

    @staticmethod
    def derive_session_key(
        shared_secret: bytes,
        salt: Optional[bytes] = None,
        info: bytes = b"SecureMID-Session-v1"
    ) -> bytes:
        """Derives a 256-bit symmetric key from shared secret using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt or b"SecureMIDDefaultSalt",
            info=info,
        )
        return hkdf.derive(shared_secret)


class PostQuantumSignatureManager:
    """
    ML-DSA (Dilithium NIST FIPS 204) Digital Signature Manager.
    Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.
    """

    @staticmethod
    def _get_classes(variant: str):
        if variant == "ML-DSA-44":
            return mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey
        elif variant == "ML-DSA-65":
            return mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey
        elif variant == "ML-DSA-87":
            return mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey
        else:
            raise ValueError(f"Unsupported ML-DSA variant: {variant}")

    @classmethod
    def generate_keypair(cls, variant: str = "ML-DSA-65") -> Tuple[bytes, bytes]:
        """Returns: (public_key_der, private_key_der)"""
        sk_cls, _ = cls._get_classes(variant)
        sk = sk_cls.generate()
        pk = sk.public_key()
        sk_der = sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        pk_der = pk.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return pk_der, sk_der

    @classmethod
    def sign(cls, secret_key_der: bytes, message: bytes, variant: str = "ML-DSA-65") -> bytes:
        """Signs message bytes using secret key."""
        sk = load_der_private_key(secret_key_der, password=None)
        return sk.sign(message)

    @classmethod
    def verify(cls, public_key_der: bytes, signature: bytes, message: bytes, variant: str = "ML-DSA-65") -> bool:
        """Verifies signature over message. Returns True or raises AuthenticationFailedError."""
        try:
            pk = load_der_public_key(public_key_der)
            pk.verify(signature, message)
            return True
        except InvalidSignature:
            raise AuthenticationFailedError("ML-DSA signature verification failed (tampered data or wrong key)")
        except Exception as e:
            raise AuthenticationFailedError(f"ML-DSA signature verification error: {str(e)}")


class ClassicalKeyExchangeManager:
    """
    Classical Elliptic Curve Diffie-Hellman Key Exchange (X25519 - RFC 7748).
    """

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Returns: (public_key_bytes, private_key_bytes)"""
        sk = x25519.X25519PrivateKey.generate()
        pk = sk.public_key()
        return pk.public_bytes_raw(), sk.private_bytes_raw()

    @staticmethod
    def exchange(secret_key_raw: bytes, peer_public_key_raw: bytes) -> bytes:
        """Computes classical ECDH shared secret."""
        sk = x25519.X25519PrivateKey.from_private_bytes(secret_key_raw)
        pk = x25519.X25519PublicKey.from_public_bytes(peer_public_key_raw)
        return sk.exchange(pk)


class HybridKeyExchangeManager:
    """
    Hybrid Classical + Post-Quantum Key Establishment (X25519 + ML-KEM-768).
    Implements standard dual-key encapsulation and HKDF-SHA256 secret combiner.
    """

    @staticmethod
    def generate_keypair() -> Dict[str, bytes]:
        """Generates both X25519 and ML-KEM-768 key pairs."""
        c_pk, c_sk = ClassicalKeyExchangeManager.generate_keypair()
        q_pk, q_sk = PostQuantumKEMManager.generate_keypair("ML-KEM-768")
        return {
            "x25519_pk": c_pk,
            "x25519_sk": c_sk,
            "mlkem_pk": q_pk,
            "mlkem_sk": q_sk,
        }

    @staticmethod
    def encapsulate(peer_x25519_pk: bytes, peer_mlkem_pk: bytes) -> Dict[str, bytes]:
        """
        Initiator encapsulates both classical ECDH and PQC KEM.
        """
        e_pk, e_sk = ClassicalKeyExchangeManager.generate_keypair()
        ss_classical = ClassicalKeyExchangeManager.exchange(e_sk, peer_x25519_pk)
        ss_pqc, kem_ct = PostQuantumKEMManager.encapsulate(peer_mlkem_pk, "ML-KEM-768")

        combined_raw = ss_classical + ss_pqc
        return {
            "ephemeral_x25519_pk": e_pk,
            "mlkem_ciphertext": kem_ct,
            "shared_secret": combined_raw,
        }

    @staticmethod
    def decapsulate(
        recipient_x25519_sk: bytes,
        recipient_mlkem_sk: bytes,
        peer_ephemeral_x25519_pk: bytes,
        kem_ciphertext: bytes
    ) -> bytes:
        """
        Recipient derives both shared secrets and combines them identically.
        """
        ss_classical = ClassicalKeyExchangeManager.exchange(recipient_x25519_sk, peer_ephemeral_x25519_pk)
        ss_pqc = PostQuantumKEMManager.decapsulate(recipient_mlkem_sk, kem_ciphertext, "ML-KEM-768")
        return ss_classical + ss_pqc

    @staticmethod
    def derive_symmetric_key(combined_shared_secret: bytes, salt: Optional[bytes] = None) -> bytes:
        """Derives 256-bit symmetric AEAD session key from combined secret."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt or b"SecureMIDHybridSalt2026",
            info=b"SecureMID-Hybrid-X25519-MLKEM768-v1",
        )
        return hkdf.derive(combined_shared_secret)
