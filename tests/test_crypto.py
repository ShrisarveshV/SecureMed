"""
Test suite for SecureMed Cryptographic Engine
"""
import unittest
from crypto_engine.ciphers import (
    SecureMedCryptoEngine,
    PostQuantumKEMManager,
    AuthenticationFailedError,
    SUPPORTED_ALGORITHMS
)

class TestCryptoEngine(unittest.TestCase):

    def test_all_algorithms_roundtrip(self):
        sample_plaintext = b'{"device_id":"SIM-PM-001","heart_rate_bpm":72,"synthetic":true}'
        aad = b"protocol=1|device=SIM-PM-001|seq=101"

        for algo in ["AES-128-CCM", "AES-128-GCM", "AES-256-GCM", "Ascon-AEAD128"]:
            with self.subTest(algorithm=algo):
                engine = SecureMedCryptoEngine(algorithm=algo)
                ct, nonce, tag, enc_ms = engine.encrypt(sample_plaintext, aad)
                
                # Check lengths
                self.assertEqual(len(tag), 16)
                self.assertTrue(len(ct) > 0)
                
                # Decrypt
                decrypted, dec_ms = engine.decrypt(ct, nonce, tag, aad)
                self.assertEqual(decrypted, sample_plaintext)

    def test_ciphertext_tampering_rejected(self):
        sample_plaintext = b'{"device_id":"SIM-PM-001","heart_rate_bpm":72}'
        aad = b"SIM-PM-001|session-001|1"

        for algo in ["AES-128-CCM", "AES-128-GCM", "AES-256-GCM", "Ascon-AEAD128"]:
            with self.subTest(algorithm=algo):
                engine = SecureMedCryptoEngine(algorithm=algo)
                ct, nonce, tag, _ = engine.encrypt(sample_plaintext, aad)
                
                # Flip 1 bit in ciphertext
                tampered_ct = bytearray(ct)
                tampered_ct[0] ^= 0x01
                
                with self.assertRaises(AuthenticationFailedError):
                    engine.decrypt(bytes(tampered_ct), nonce, tag, aad)

    def test_tag_tampering_rejected(self):
        sample_plaintext = b'{"device_id":"SIM-PM-001","heart_rate_bpm":72}'
        aad = b"SIM-PM-001|session-001|1"

        for algo in ["AES-128-CCM", "AES-128-GCM", "AES-256-GCM", "Ascon-AEAD128"]:
            with self.subTest(algorithm=algo):
                engine = SecureMedCryptoEngine(algorithm=algo)
                ct, nonce, tag, _ = engine.encrypt(sample_plaintext, aad)
                
                # Flip 1 bit in tag
                tampered_tag = bytearray(tag)
                tampered_tag[-1] ^= 0x01
                
                with self.assertRaises(AuthenticationFailedError):
                    engine.decrypt(ct, nonce, bytes(tampered_tag), aad)

    def test_aad_tampering_rejected(self):
        sample_plaintext = b'{"device_id":"SIM-PM-001","heart_rate_bpm":72}'
        aad = b"SIM-PM-001|session-001|1"
        tampered_aad = b"SIM-PM-001|session-001|2"  # Altered sequence number in AAD!

        for algo in ["AES-128-CCM", "AES-128-GCM", "AES-256-GCM", "Ascon-AEAD128"]:
            with self.subTest(algorithm=algo):
                engine = SecureMedCryptoEngine(algorithm=algo)
                ct, nonce, tag, _ = engine.encrypt(sample_plaintext, aad)
                
                with self.assertRaises(AuthenticationFailedError):
                    engine.decrypt(ct, nonce, tag, tampered_aad)

    def test_wrong_key_rejected(self):
        sample_plaintext = b'{"device_id":"SIM-PM-001","heart_rate_bpm":72}'
        aad = b"SIM-PM-001|session-001|1"

        for algo in ["AES-128-CCM", "AES-128-GCM", "AES-256-GCM", "Ascon-AEAD128"]:
            with self.subTest(algorithm=algo):
                engine1 = SecureMedCryptoEngine(algorithm=algo)
                engine2 = SecureMedCryptoEngine(algorithm=algo)  # different random key
                
                ct, nonce, tag, _ = engine1.encrypt(sample_plaintext, aad)
                
                with self.assertRaises(AuthenticationFailedError):
                    engine2.decrypt(ct, nonce, tag, aad)

    def test_ml_kem_768_key_derivation(self):
        # Laptop creates keypair
        pk, sk = PostQuantumKEMManager.generate_keypair()
        
        # Phone encapsulates shared secret
        ss_sender, kem_ct = PostQuantumKEMManager.encapsulate(pk)
        
        # Laptop decapsulates shared secret
        ss_receiver = PostQuantumKEMManager.decapsulate(sk, kem_ct)
        
        self.assertEqual(ss_sender, ss_receiver)
        
        # Both derive symmetric key with HKDF-SHA256
        k_sender = PostQuantumKEMManager.derive_session_key(ss_sender)
        k_receiver = PostQuantumKEMManager.derive_session_key(ss_receiver)
        
        self.assertEqual(k_sender, k_receiver)
        self.assertEqual(len(k_sender), 32)

if __name__ == "__main__":
    unittest.main()
