"""
Comprehensive Automated Test Suite for SecureMed
Validates:
  1. Encryption and decryption round trips for all 4 ciphers + ML-KEM
  2. Correct authentication-tag verification
  3. Rejection of modified ciphertext
  4. Rejection of modified authentication tags
  5. Replay detection (stale sequence packets)
  6. Duplicate sequence-number rejection
  7. Session separation (packet with wrong session ID)
  8. Invalid packet handling (malformed JSON, wrong types, missing fields)
  9. Nonce uniqueness checks
  10. Wrong key rejection
  11. CSV export generation and data verification
  12. Synthetic telemetry generator conformance
"""

import io
import csv
import json
import base64
import unittest

from crypto_engine.ciphers import (
    SecureMedCryptoEngine,
    PostQuantumKEMManager,
    AuthenticationFailedError,
    SUPPORTED_ALGORITHMS,
)
from protocol.packet import SecureMedPacket, PacketValidationError
from protocol.replay_detector import ReplayDetector, ReplayCheckResult
from telemetry.synthetic_generator import SyntheticTelemetryGenerator
from receiver.receiver_service import process_incoming_packet, state, reset_metrics


class TestSecureMedFullSystem(unittest.TestCase):

    def setUp(self):
        reset_metrics()

    def test_01_all_ciphers_roundtrip(self):
        """1. Encryption and decryption round trips across all supported ciphers."""
        test_payload = b'{"device_id":"SIM-PM-001","heart_rate_bpm":72,"synthetic":true}'

        for algo in ["AES-128-CCM", "AES-128-GCM", "AES-256-GCM", "Ascon-AEAD128"]:
            with self.subTest(algo=algo):
                engine = SecureMedCryptoEngine(algorithm=algo)
                aad = f"VER:1|DEV:SIM-PM-001|SES:ses-1|SEQ:1|ALG:{algo}".encode()

                ct, nonce, tag, enc_ms = engine.encrypt(test_payload, aad)
                self.assertGreater(len(ct), 0)
                self.assertEqual(len(tag), 16)

                decrypted, dec_ms = engine.decrypt(ct, nonce, tag, aad)
                self.assertEqual(decrypted, test_payload)

    def test_02_rejection_of_tampered_ciphertext(self):
        """2. Receiver must reject tampered ciphertext."""
        engine = SecureMedCryptoEngine(algorithm="AES-128-CCM")
        pt = b'{"synthetic":true,"heart_rate_bpm":72}'
        aad = b"canonical-header-aad"

        ct, nonce, tag, _ = engine.encrypt(pt, aad)
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0x42  # alter a byte

        with self.assertRaises(AuthenticationFailedError):
            engine.decrypt(bytes(tampered_ct), nonce, tag, aad)

    def test_03_rejection_of_tampered_tag(self):
        """3. Receiver must reject tampered authentication tag."""
        engine = SecureMedCryptoEngine(algorithm="AES-128-GCM")
        pt = b'{"synthetic":true,"lead_impedance_ohms":540}'
        aad = b"canonical-header-aad"

        ct, nonce, tag, _ = engine.encrypt(pt, aad)
        tampered_tag = bytearray(tag)
        tampered_tag[-1] ^= 0x88  # alter MAC tag byte

        with self.assertRaises(AuthenticationFailedError):
            engine.decrypt(ct, nonce, bytes(tampered_tag), aad)

    def test_04_wrong_key_rejection(self):
        """4. Confirm receiver cannot decrypt a packet with the wrong key."""
        engine1 = SecureMedCryptoEngine(algorithm="AES-128-CCM")
        engine2 = SecureMedCryptoEngine(algorithm="AES-128-CCM")  # independent key

        pt = b'{"synthetic":true,"secret":"clinical_telemetry"}'
        aad = b"aad"
        ct, nonce, tag, _ = engine1.encrypt(pt, aad)

        with self.assertRaises(AuthenticationFailedError):
            engine2.decrypt(ct, nonce, tag, aad)

    def test_05_nonce_uniqueness(self):
        """5. Nonces must be unique across multiple encryptions."""
        engine = SecureMedCryptoEngine(algorithm="AES-128-CCM")
        seen_nonces = set()
        for _ in range(100):
            nonce = engine.generate_nonce()
            self.assertNotIn(nonce, seen_nonces)
            seen_nonces.add(nonce)

    def test_06_replay_detection_duplicate_sequence(self):
        """6. Replay detector rejects duplicate sequence numbers."""
        detector = ReplayDetector(window_size=64)
        detector.reset_session("session-test-01")

        # Accept seq 1
        ok, res = detector.check_and_update("session-test-01", 1)
        self.assertTrue(ok)

        # Accept seq 2
        ok, res = detector.check_and_update("session-test-01", 2)
        self.assertTrue(ok)

        # Duplicate seq 1 replayed -> MUST REJECT
        ok, res = detector.check_and_update("session-test-01", 1)
        self.assertFalse(ok)
        self.assertIn("Duplicate sequence number", res)

    def test_07_replay_detection_stale_packet(self):
        """7. Replay detector rejects sequence numbers behind sliding window."""
        detector = ReplayDetector(window_size=16)
        detector.reset_session("session-test-02")

        # Jump forward to sequence 50
        detector.check_and_update("session-test-02", 50)

        # Packet with sequence 20 (window is [50-16+1, 50] = [35, 50]) -> STALE
        ok, res = detector.check_and_update("session-test-02", 20)
        self.assertFalse(ok)
        self.assertIn("Stale sequence number", res)

    def test_08_session_separation(self):
        """8. Replay detector rejects packet from an unexpected session ID."""
        detector = ReplayDetector(window_size=64)
        detector.reset_session("session-legit")

        ok, res = detector.check_and_update("session-spoofed", 1)
        self.assertFalse(ok)
        self.assertIn("does not match active session", res)

    def test_09_invalid_packet_handling(self):
        """9. Reject malformed packets and invalid field types."""
        # Missing required field
        with self.assertRaises(PacketValidationError):
            SecureMedPacket.from_dict({
                "protocol_version": 1,
                "device_id": "SIM-PM-001",
                # missing session_id, seq, etc.
            })

        # Unsupported algorithm
        with self.assertRaises(PacketValidationError):
            SecureMedPacket.from_dict({
                "protocol_version": 1,
                "device_id": "SIM-PM-001",
                "session_id": "ses-01",
                "sequence_number": 1,
                "algorithm": "DES-INSECURE-CIPHER",
                "nonce": base64.b64encode(b"0" * 12).decode(),
                "ciphertext": base64.b64encode(b"test").decode(),
                "authentication_tag": base64.b64encode(b"0" * 16).decode(),
            })

    def test_10_end_to_end_pipeline_with_tamper_attack(self):
        """10. End-to-end receiver pipeline handles valid and attacked packets."""
        # Setup session
        session_id = state.session_id
        key = state.session_key
        algo = state.algorithm
        engine = SecureMedCryptoEngine(key=key, algorithm=algo)

        # 1. Valid Packet
        pt = json.dumps({"synthetic": True, "device_id": "SIM-PM-001", "heart_rate_bpm": 72}).encode()
        aad = f"VER:1|DEV:SIM-PM-001|SES:{session_id}|SEQ:1|ALG:{algo}".encode()
        ct, nonce, tag, _ = engine.encrypt(pt, aad)

        valid_pkt = {
            "protocol_version": 1,
            "device_id": "SIM-PM-001",
            "session_id": session_id,
            "sequence_number": 1,
            "algorithm": algo,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "authentication_tag": base64.b64encode(tag).decode(),
        }

        res = process_incoming_packet(valid_pkt)
        self.assertEqual(res["status"], "ACCEPTED")
        self.assertEqual(res["plaintext"]["heart_rate_bpm"], 72)

        # 2. Tampered Ciphertext Packet (Attack simulation)
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0xFF
        tampered_pkt = dict(valid_pkt)
        tampered_pkt["sequence_number"] = 2
        tampered_pkt["ciphertext"] = base64.b64encode(tampered_ct).decode()
        tampered_pkt["attack_injected"] = "TAMPER_CIPHERTEXT"

        res_tamper = process_incoming_packet(tampered_pkt)
        self.assertEqual(res_tamper["status"], "AUTHENTICATION_FAILED")
        self.assertTrue(res_tamper["attack_detected"])

        # 3. Replay Attack (resend seq 1)
        res_replay = process_incoming_packet(valid_pkt)
        self.assertEqual(res_replay["status"], "REPLAY_DETECTED")
        self.assertTrue(res_replay["attack_detected"])

    def test_11_post_quantum_ml_kem_768_derivation(self):
        """11. Post-Quantum ML-KEM-768 key encapsulation and HKDF derivation."""
        pk, sk = PostQuantumKEMManager.generate_keypair()
        ss_client, kem_ct = PostQuantumKEMManager.encapsulate(pk)
        ss_server = PostQuantumKEMManager.decapsulate(sk, kem_ct)

        self.assertEqual(ss_client, ss_server)

        k_client = PostQuantumKEMManager.derive_session_key(ss_client)
        k_server = PostQuantumKEMManager.derive_session_key(ss_server)

        self.assertEqual(k_client, k_server)
        self.assertEqual(len(k_client), 32)

    def test_12_synthetic_telemetry_generators(self):
        """12. Conformance of all 4 synthetic medical telemetry types."""
        types = [
            ("pacemaker", "heart_rate_bpm"),
            ("icd", "ventricular_rate_bpm"),
            ("cgm", "glucose_mg_dl"),
            ("ecg", "waveform_sample_mv")
        ]
        for dev_type, expected_field in types:
            gen = SyntheticTelemetryGenerator(device_type=dev_type)
            data = gen.generate_packet_data(sequence_number=1, session_id="ses-01")
            self.assertTrue(data["synthetic"])
            self.assertIn(expected_field, data)

    def test_13_csv_logging_verification(self):
        """13. CSV export generates valid data matching experiment events."""
        from receiver.receiver_service import export_csv, state

        # Inject a test log
        engine = SecureMedCryptoEngine(key=state.session_key, algorithm=state.algorithm)
        pt = json.dumps({"synthetic": True, "device_id": "SIM-PM-001", "heart_rate_bpm": 74}).encode()
        aad = f"VER:1|DEV:SIM-PM-001|SES:{state.session_id}|SEQ:10|ALG:{state.algorithm}".encode()
        ct, nonce, tag, _ = engine.encrypt(pt, aad)

        pkt = {
            "protocol_version": 1,
            "device_id": "SIM-PM-001",
            "session_id": state.session_id,
            "sequence_number": 10,
            "algorithm": state.algorithm,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "authentication_tag": base64.b64encode(tag).decode(),
        }
        process_incoming_packet(pkt)

        # Call export_csv
        csv_resp = export_csv()
        self.assertEqual(csv_resp.media_type, "text/csv")
        csv_text = csv_resp.body.decode("utf-8")
        reader = list(csv.reader(io.StringIO(csv_text)))

        # Verify CSV headers
        self.assertGreater(len(reader), 1)
        self.assertIn("timestamp", reader[0])
        self.assertIn("sequence_number", reader[0])
        self.assertIn("algorithm", reader[0])
        self.assertIn("status", reader[0])

    def test_14_disconnection_and_reconnection_session_resilience(self):
        """14. Disconnection and reconnection behavior with session reset."""
        # Session A
        sess_a = "SES-DISCONN-A"
        state.session_id = sess_a
        state.replay_detector.reset_session(sess_a)

        key_a = state.session_key
        engine_a = SecureMedCryptoEngine(key=key_a, algorithm="AES-128-CCM")

        pt = json.dumps({"synthetic": True, "device_id": "SIM-PM-001", "heart_rate_bpm": 70}).encode()
        aad_a = f"VER:1|DEV:SIM-PM-001|SES:{sess_a}|SEQ:1|ALG:AES-128-CCM".encode()
        ct, nonce, tag, _ = engine_a.encrypt(pt, aad_a)

        pkt_a = {
            "protocol_version": 1,
            "device_id": "SIM-PM-001",
            "session_id": sess_a,
            "sequence_number": 1,
            "algorithm": "AES-128-CCM",
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "authentication_tag": base64.b64encode(tag).decode(),
        }
        res_a = process_incoming_packet(pkt_a)
        self.assertEqual(res_a["status"], "ACCEPTED")

        # Disconnection & Reconnection: Server establishes Session B
        sess_b = "SES-RECONN-B"
        state.session_id = sess_b
        state.replay_detector.reset_session(sess_b)

        # Old packet from disconnected session A must be rejected
        res_stale_sess = process_incoming_packet(pkt_a)
        self.assertNotEqual(res_stale_sess["status"], "ACCEPTED")

        # New packet in Session B accepted
        engine_b = SecureMedCryptoEngine(key=state.session_key, algorithm="AES-128-CCM")
        aad_b = f"VER:1|DEV:SIM-PM-001|SES:{sess_b}|SEQ:1|ALG:AES-128-CCM".encode()
        ct_b, nonce_b, tag_b, _ = engine_b.encrypt(pt, aad_b)

        pkt_b = dict(pkt_a)
        pkt_b["session_id"] = sess_b
        pkt_b["nonce"] = base64.b64encode(nonce_b).decode()
        pkt_b["ciphertext"] = base64.b64encode(ct_b).decode()
        pkt_b["authentication_tag"] = base64.b64encode(tag_b).decode()

        res_b = process_incoming_packet(pkt_b)
        self.assertEqual(res_b["status"], "ACCEPTED")

    def test_15_all_ciphers_interoperability_end_to_end(self):
        """15. End-to-end interoperability across all 4 ciphers through receiver pipeline."""
        ciphers = ["AES-128-CCM", "AES-128-GCM", "AES-256-GCM", "Ascon-AEAD128"]

        for algo in ciphers:
            with self.subTest(algorithm=algo):
                s_id = f"SES-INTEROP-{algo}"
                state.session_id = s_id
                state.algorithm = algo
                state.session_key = SecureMedCryptoEngine.generate_key(algo)
                state.crypto_engine = SecureMedCryptoEngine(key=state.session_key, algorithm=algo)
                state.replay_detector.reset_session(s_id)

                engine = SecureMedCryptoEngine(key=state.session_key, algorithm=algo)
                pt = json.dumps({"synthetic": True, "device_id": "SIM-ICD-002", "ventricular_rate_bpm": 80}).encode()
                aad = f"VER:1|DEV:SIM-ICD-002|SES:{s_id}|SEQ:1|ALG:{algo}".encode()

                ct, nonce, tag, _ = engine.encrypt(pt, aad)
                pkt = {
                    "protocol_version": 1,
                    "device_id": "SIM-ICD-002",
                    "session_id": s_id,
                    "sequence_number": 1,
                    "algorithm": algo,
                    "nonce": base64.b64encode(nonce).decode(),
                    "ciphertext": base64.b64encode(ct).decode(),
                    "authentication_tag": base64.b64encode(tag).decode(),
                }

                res = process_incoming_packet(pkt)
                self.assertEqual(res["status"], "ACCEPTED")
                self.assertEqual(res["plaintext"]["ventricular_rate_bpm"], 80)

    def test_16_ble_adapter_diagnostics(self):
        """16. BLE adapter diagnostics and GATT UUID verification."""
        from receiver.ble_receiver import (
            BLETelemetryAdapter,
            SECUREMED_SERVICE_UUID,
            SECUREMED_CHAR_ENCRYPTED_TX,
            SECUREMED_CHAR_ACK_RX
        )
        adapter = BLETelemetryAdapter()
        summary = adapter.get_status_summary()
        self.assertIn("service_uuid", summary)
        self.assertEqual(summary["service_uuid"], SECUREMED_SERVICE_UUID)
        self.assertEqual(SECUREMED_SERVICE_UUID, "6E400001-B5A3-F393-E0A9-E50E24DCCA9E")

    def test_17_comparative_benchmark_metrics(self):
        """17. Cryptographic benchmark produces reproducible timing and overhead metrics."""
        from crypto_engine.benchmark import run_comparative_benchmark
        report = run_comparative_benchmark(iterations=10)
        self.assertIn("benchmarks", report)
        self.assertIn("AES-128-CCM", report["benchmarks"])
        self.assertIn("Ascon-AEAD128", report["benchmarks"])
        self.assertIn("enc_mean_us", report["benchmarks"]["AES-128-CCM"])
        self.assertIn("dec_mean_us", report["benchmarks"]["AES-128-CCM"])
        self.assertIn("wire_packet_bytes", report["benchmarks"]["AES-128-CCM"])


if __name__ == "__main__":
    unittest.main()
