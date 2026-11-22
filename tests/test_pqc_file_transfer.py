"""
Tests for Secure MID Post-Quantum Cryptography, Hybrid Key Exchange,
Real File Encryption, and Security Validation Engine.
"""

import unittest
import os
import hashlib
from crypto_engine.ciphers import (
    SecureMedCryptoEngine,
    PostQuantumKEMManager,
    PostQuantumSignatureManager,
    ClassicalKeyExchangeManager,
    HybridKeyExchangeManager,
    AuthenticationFailedError,
    AEAD_ALGORITHMS,
    PQC_KEM_ALGORITHMS,
    PQC_SIGNATURE_ALGORITHMS,
)
from crypto_engine.measurements import HardwareDetector, calculate_repetition_statistics
from crypto_engine.security_validation import run_full_security_validation_suite
from receiver.file_transfer import SecureMIDFileContainer, file_transfer_mgr


class TestSecureMIDAdvancedPQC(unittest.TestCase):

    def test_01_all_aead_algorithms(self):
        """Verify all AEAD ciphers encrypt and decrypt correctly."""
        for algo in AEAD_ALGORITHMS:
            engine = SecureMedCryptoEngine(algorithm=algo)
            plaintext = f"Medical diagnostic test data for {algo}".encode("utf-8")
            aad = b"HEADER:TEST_01"
            ct, nonce, tag, _ = engine.encrypt(plaintext, aad)
            decrypted, _ = engine.decrypt(ct, nonce, tag, aad)
            self.assertEqual(plaintext, decrypted, f"Decryption failed for {algo}")

    def test_02_ml_kem_suite(self):
        """Verify ML-KEM-512, ML-KEM-768, and ML-KEM-1024."""
        for variant in PQC_KEM_ALGORITHMS:
            pk, sk = PostQuantumKEMManager.generate_keypair(variant)
            ss_sender, ct = PostQuantumKEMManager.encapsulate(pk, variant)
            ss_receiver = PostQuantumKEMManager.decapsulate(sk, ct, variant)
            self.assertEqual(ss_sender, ss_receiver, f"KEM failed for {variant}")
            derived = PostQuantumKEMManager.derive_session_key(ss_sender)
            self.assertEqual(len(derived), 32)

    def test_03_ml_dsa_suite(self):
        """Verify ML-DSA-44, ML-DSA-65, and ML-DSA-87."""
        message = b"Patient Telemetry Firmware Image v2.4.1"
        for variant in PQC_SIGNATURE_ALGORITHMS:
            pk, sk = PostQuantumSignatureManager.generate_keypair(variant)
            sig = PostQuantumSignatureManager.sign(sk, message, variant)
            self.assertTrue(PostQuantumSignatureManager.verify(pk, sig, message, variant))
            # Test tampering
            with self.assertRaises(AuthenticationFailedError):
                PostQuantumSignatureManager.verify(pk, sig, message + b"_TAMPERED", variant)

    def test_04_hybrid_x25519_mlkem768(self):
        """Verify hybrid key exchange combining X25519 and ML-KEM-768."""
        alice = HybridKeyExchangeManager.generate_keypair()
        bob = HybridKeyExchangeManager.encapsulate(alice["x25519_pk"], alice["mlkem_pk"])
        alice_combined = HybridKeyExchangeManager.decapsulate(
            alice["x25519_sk"], alice["mlkem_sk"], bob["ephemeral_x25519_pk"], bob["mlkem_ciphertext"]
        )
        self.assertEqual(alice_combined, bob["shared_secret"])
        k_alice = HybridKeyExchangeManager.derive_symmetric_key(alice_combined)
        k_bob = HybridKeyExchangeManager.derive_symmetric_key(bob["shared_secret"])
        self.assertEqual(k_alice, k_bob)
        self.assertEqual(len(k_alice), 32)

    def test_05_file_container_and_integrity(self):
        """Verify real file container encryption, decryption, and SHA-256 match."""
        payload = b"CRITICAL MEDICAL REPORT: Potassium 4.2 mEq/L, Sodium 138 mEq/L, Normal Sinus Rhythm."
        container = SecureMIDFileContainer.create(
            filename="patient_report.dat",
            plaintext_bytes=payload,
            algorithm="AES-256-GCM",
            workflow="HYBRID_PQC_AEAD",
            sign_with_pqc=True,
            pqc_sig_variant="ML-DSA-65",
        )
        self.assertEqual(container["original_file_size_bytes"], len(payload))
        self.assertEqual(container["original_sha256"], hashlib.sha256(payload).hexdigest())

        decrypted = SecureMIDFileContainer.decrypt(container)
        self.assertEqual(decrypted["status"], "DECRYPTED_AND_VERIFIED")
        self.assertTrue(decrypted["integrity_matched"])
        self.assertTrue(decrypted["signature_verified"])
        self.assertEqual(decrypted["plaintext_bytes"], payload)

    def test_06_security_validation_suite(self):
        """Verify full 12-test security validation suite executes and passes."""
        report = run_full_security_validation_suite("AES-128-GCM")
        self.assertEqual(report["total_tests"], 12)
        self.assertEqual(report["passed"], 12)
        self.assertEqual(report["failed"], 0)

    def test_07_energy_measurement_policy(self):
        """Verify energy is marked Unavailable when physical meter is absent."""
        hw = HardwareDetector.get_hardware_profile()
        p_info = hw["power_instrumentation"]
        self.assertEqual(p_info["status"], "Unavailable")
        self.assertIn("Unavailable", p_info["reason"])

    def test_08_pqc_energy_greater_than_aead(self):
        """Verify that energy consumed by post-quantum algorithms is strictly greater than AEAD ciphers."""
        payload = b"Medical diagnostic telemetry payload for energy benchmark analysis."
        
        # 1. Standard AEAD direct encryption
        aead_container = SecureMIDFileContainer.create(
            filename="aead_test.dat",
            plaintext_bytes=payload,
            algorithm="AES-128-GCM",
            workflow="AEAD_DIRECT",
        )
        aead_enc_uj = aead_container["energy_consumption"]["energy_uj"]
        
        # 2. Hybrid Post-Quantum Key Establishment (X25519 + ML-KEM-768)
        pqc_container = SecureMIDFileContainer.create(
            filename="pqc_test.dat",
            plaintext_bytes=payload,
            algorithm="AES-256-GCM",
            workflow="HYBRID_PQC_AEAD",
            sign_with_pqc=True,
            pqc_sig_variant="ML-DSA-65",
        )
        pqc_enc_uj = pqc_container["energy_consumption"]["energy_uj"]
        
        # Assert post-quantum encryption energy is strictly greater than AEAD
        self.assertGreater(
            pqc_enc_uj,
            aead_enc_uj,
            f"Expected PQC encryption energy ({pqc_enc_uj} uJ) to exceed AEAD energy ({aead_enc_uj} uJ)",
        )

        # 3. Verify on decryption as well
        aead_dec = SecureMIDFileContainer.decrypt(aead_container)
        pqc_dec = SecureMIDFileContainer.decrypt(pqc_container)
        aead_dec_uj = aead_dec["energy_consumption"]["energy_uj"]
        pqc_dec_uj = pqc_dec["energy_consumption"]["energy_uj"]

        self.assertGreater(
            pqc_dec_uj,
            aead_dec_uj,
            f"Expected PQC decryption energy ({pqc_dec_uj} uJ) to exceed AEAD energy ({aead_dec_uj} uJ)",
        )


if __name__ == "__main__":
    unittest.main()
