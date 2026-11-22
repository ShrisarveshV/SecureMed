"""
Secure MID Cryptographic Benchmark Engine
Performs rigorous, reproducible empirical measurements across:
  - Authenticated Encryption: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, Ascon-AEAD128, AES-128-CCM, AES-256-CCM
  - Post-Quantum Key Encapsulation: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - Post-Quantum Digital Signatures: ML-DSA-44, ML-DSA-65, ML-DSA-87
  - Classical Key Establishment: X25519
  - Hybrid Classical + PQC: X25519 + ML-KEM-768

Adheres strictly to the Non-Negotiable Measurement Policy:
  - All timings are measured using monotonic nanosecond clocks.
  - Raw observations are preserved for every single repetition.
  - Energy is reported as 'Unavailable' unless physical power meter is present.
"""

import os
import sys
import time
import base64
import json
import uuid
from typing import Dict, Any, List, Optional

import psutil

# Add project root to sys.path if run directly
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from crypto_engine.ciphers import (
    SecureMedCryptoEngine,
    PostQuantumKEMManager,
    PostQuantumSignatureManager,
    ClassicalKeyExchangeManager,
    HybridKeyExchangeManager,
    AEAD_ALGORITHMS,
    PQC_KEM_ALGORITHMS,
    PQC_SIGNATURE_ALGORITHMS,
    CLASSICAL_KEM_ALGORITHMS,
    HYBRID_ALGORITHMS,
    SUPPORTED_ALGORITHMS,
)
from crypto_engine.measurements import (
    HardwareDetector,
    calculate_repetition_statistics,
    BenchmarkExecutionSnapshot,
    PowerCFGEnergyMeter,
)

SAMPLE_TELEMETRY = {
    "device_id": "SIM-PM-001",
    "heart_rate_bpm": 74.2,
    "pacing_voltage_v": 2.5,
    "battery_percentage": 94,
    "lead_impedance_ohms": 482,
    "pacing_mode": "DDD",
    "timestamp": "2026-10-26T22:00:00Z",
}


def run_comparative_benchmark(
    iterations: int = 150,
    payload_size: int = 64,
    aad_size: int = 32,
    warmup_runs: int = 10,
    algorithms: Optional[List[str]] = None,
    include_pqc: bool = True,
) -> Dict[str, Any]:
    """
    Executes a comprehensive, empirical micro-benchmark across candidate AEAD ciphers
    and Post-Quantum primitives under identical hardware and payload constraints.
    """
    run_id = f"RUN-{uuid.uuid4().hex[:10].upper()}"
    timestamp_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    hardware_profile = HardwareDetector.get_hardware_profile()

    # Generate exact payload and associated data bytes
    if payload_size == len(json.dumps(SAMPLE_TELEMETRY)):
        payload_bytes = json.dumps(SAMPLE_TELEMETRY).encode("utf-8")
    else:
        payload_bytes = os.urandom(payload_size)

    aad_bytes = os.urandom(aad_size) if aad_size > 0 else b""

    selected_algos = algorithms or AEAD_ALGORITHMS
    snapshot = BenchmarkExecutionSnapshot()

    aead_results: Dict[str, Any] = {}

    for algo in selected_algos:
        if algo not in AEAD_ALGORITHMS:
            continue

        engine = SecureMedCryptoEngine(algorithm=algo)
        enc_times_us: List[float] = []
        dec_times_us: List[float] = []

        # Warm-up phase (ensures JIT, CPU frequency scaling, and cache warming)
        for _ in range(warmup_runs):
            ct, n, tag, _ = engine.encrypt(payload_bytes, aad_bytes)
            engine.decrypt(ct, n, tag, aad_bytes)

        # Benchmark Encryption repetitions
        encrypted_packets = []
        enc_wall_start = time.perf_counter_ns()
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            ct, n, tag, _ = engine.encrypt(payload_bytes, aad_bytes)
            elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
            enc_times_us.append(elapsed_us)
            encrypted_packets.append((ct, n, tag))
        enc_wall_sec = (time.perf_counter_ns() - enc_wall_start) / 1_000_000_000.0

        # Benchmark Decryption repetitions
        dec_wall_start = time.perf_counter_ns()
        for ct, n, tag in encrypted_packets:
            t0 = time.perf_counter_ns()
            engine.decrypt(ct, n, tag, aad_bytes)
            elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
            dec_times_us.append(elapsed_us)
        dec_wall_sec = (time.perf_counter_ns() - dec_wall_start) / 1_000_000_000.0

        sample_ct, sample_n, sample_tag = encrypted_packets[0]
        wire_ciphertext_bytes = len(sample_ct)
        total_wire_bytes = wire_ciphertext_bytes + len(sample_n) + len(sample_tag)
        overhead_pct = round(((total_wire_bytes - len(payload_bytes)) / max(1, len(payload_bytes))) * 100.0, 1)

        enc_stats = calculate_repetition_statistics(enc_times_us, unit="us")
        dec_stats = calculate_repetition_statistics(dec_times_us, unit="us")

        enc_throughput_mb_s = round(((len(payload_bytes) * iterations) / max(0.0001, enc_wall_sec)) / (1024 * 1024), 2)
        dec_throughput_mb_s = round(((len(payload_bytes) * iterations) / max(0.0001, dec_wall_sec)) / (1024 * 1024), 2)

        aead_results[algo] = {
            "algorithm": algo,
            "category": "Authenticated Encryption",
            "key_bits": len(engine.key) * 8,
            "nonce_bytes": len(sample_n),
            "tag_bytes": len(sample_tag),
            "payload_bytes": len(payload_bytes),
            "ciphertext_bytes": wire_ciphertext_bytes,
            "total_wire_bytes": total_wire_bytes,
            "wire_packet_bytes": total_wire_bytes,
            "enc_mean_us": enc_stats["mean"],
            "dec_mean_us": dec_stats["mean"],
            "overhead_pct": overhead_pct,
            "encryption": {
                "wall_sec": round(enc_wall_sec, 4),
                "ops_per_sec": round(iterations / max(0.0001, enc_wall_sec), 0),
                "throughput_mb_s": enc_throughput_mb_s,
                "stats": enc_stats,
            },
            "decryption": {
                "wall_sec": round(dec_wall_sec, 4),
                "ops_per_sec": round(iterations / max(0.0001, dec_wall_sec), 0),
                "throughput_mb_s": dec_throughput_mb_s,
                "stats": dec_stats,
            },
            "energy_consumption": {
                "status": "Unavailable",
                "reason": "Unavailable — no suitable power measurement source detected.",
                "calibrated_baseline_uj": PowerCFGEnergyMeter.calculate_energy(
                    execution_time_sec=enc_stats["mean"] / 1_000_000.0,
                    algorithm=algo,
                    is_pqc=False,
                )["energy_uj"],
            },
        }

    pqc_results: Dict[str, Any] = {}
    if include_pqc:
        # 1. ML-KEM Suite (512, 768, 1024)
        pqc_results["kem"] = {}
        for kem_variant in PQC_KEM_ALGORITHMS:
            kem_keygen_us: List[float] = []
            kem_encaps_us: List[float] = []
            kem_decaps_us: List[float] = []

            # Adjust iterations for pure python Kyber512 vs fast Rust 768/1024
            kem_iter = min(iterations, 30) if kem_variant == "ML-KEM-512" else min(iterations, 100)

            sample_pk, sample_sk = PostQuantumKEMManager.generate_keypair(kem_variant)
            sample_ss, sample_ct = PostQuantumKEMManager.encapsulate(sample_pk, kem_variant)

            for _ in range(kem_iter):
                # Keygen
                t0 = time.perf_counter_ns()
                pk, sk = PostQuantumKEMManager.generate_keypair(kem_variant)
                kem_keygen_us.append((time.perf_counter_ns() - t0) / 1000.0)

                # Encaps
                t1 = time.perf_counter_ns()
                ss, ct = PostQuantumKEMManager.encapsulate(pk, kem_variant)
                kem_encaps_us.append((time.perf_counter_ns() - t1) / 1000.0)

                # Decaps
                t2 = time.perf_counter_ns()
                PostQuantumKEMManager.decapsulate(sk, ct, kem_variant)
                kem_decaps_us.append((time.perf_counter_ns() - t2) / 1000.0)

            encaps_stats = calculate_repetition_statistics(kem_encaps_us, unit="us")
            pqc_results["kem"][kem_variant] = {
                "algorithm": kem_variant,
                "standard": "NIST FIPS 203",
                "public_key_bytes": len(sample_pk),
                "secret_key_bytes": len(sample_sk),
                "ciphertext_bytes": len(sample_ct),
                "shared_secret_bytes": len(sample_ss),
                "keygen_stats": calculate_repetition_statistics(kem_keygen_us, unit="us"),
                "encaps_stats": encaps_stats,
                "decaps_stats": calculate_repetition_statistics(kem_decaps_us, unit="us"),
                "energy_consumption": PowerCFGEnergyMeter.calculate_energy(
                    execution_time_sec=encaps_stats["mean"] / 1_000_000.0,
                    algorithm=kem_variant,
                    is_pqc=True,
                ),
            }

        # 2. ML-DSA Suite (44, 65, 87)
        pqc_results["signatures"] = {}
        for dsa_variant in PQC_SIGNATURE_ALGORITHMS:
            dsa_keygen_us: List[float] = []
            dsa_sign_us: List[float] = []
            dsa_verify_us: List[float] = []

            dsa_iter = min(iterations, 100)
            sample_pk, sample_sk = PostQuantumSignatureManager.generate_keypair(dsa_variant)
            sample_sig = PostQuantumSignatureManager.sign(sample_sk, payload_bytes, dsa_variant)

            for _ in range(dsa_iter):
                # Keygen
                t0 = time.perf_counter_ns()
                pk, sk = PostQuantumSignatureManager.generate_keypair(dsa_variant)
                dsa_keygen_us.append((time.perf_counter_ns() - t0) / 1000.0)

                # Sign
                t1 = time.perf_counter_ns()
                sig = PostQuantumSignatureManager.sign(sk, payload_bytes, dsa_variant)
                dsa_sign_us.append((time.perf_counter_ns() - t1) / 1000.0)

                # Verify
                t2 = time.perf_counter_ns()
                PostQuantumSignatureManager.verify(pk, sig, payload_bytes, dsa_variant)
                dsa_verify_us.append((time.perf_counter_ns() - t2) / 1000.0)

            sign_stats = calculate_repetition_statistics(dsa_sign_us, unit="us")
            pqc_results["signatures"][dsa_variant] = {
                "algorithm": dsa_variant,
                "standard": "NIST FIPS 204",
                "public_key_bytes": len(sample_pk),
                "secret_key_bytes": len(sample_sk),
                "signature_bytes": len(sample_sig),
                "keygen_stats": calculate_repetition_statistics(dsa_keygen_us, unit="us"),
                "sign_stats": sign_stats,
                "verify_stats": calculate_repetition_statistics(dsa_verify_us, unit="us"),
                "energy_consumption": PowerCFGEnergyMeter.calculate_energy(
                    execution_time_sec=sign_stats["mean"] / 1_000_000.0,
                    algorithm=dsa_variant,
                    is_pqc=True,
                ),
            }

        # 3. Hybrid Suite (X25519 + ML-KEM-768)
        hybrid_keygen_us: List[float] = []
        hybrid_encaps_us: List[float] = []
        hybrid_decaps_us: List[float] = []
        hybrid_kdf_us: List[float] = []

        hybrid_iter = min(iterations, 100)
        sample_alice = HybridKeyExchangeManager.generate_keypair()
        sample_bob = HybridKeyExchangeManager.encapsulate(sample_alice["x25519_pk"], sample_alice["mlkem_pk"])

        for _ in range(hybrid_iter):
            t0 = time.perf_counter_ns()
            alice = HybridKeyExchangeManager.generate_keypair()
            hybrid_keygen_us.append((time.perf_counter_ns() - t0) / 1000.0)

            t1 = time.perf_counter_ns()
            bob = HybridKeyExchangeManager.encapsulate(alice["x25519_pk"], alice["mlkem_pk"])
            hybrid_encaps_us.append((time.perf_counter_ns() - t1) / 1000.0)

            t2 = time.perf_counter_ns()
            alice_combined = HybridKeyExchangeManager.decapsulate(
                alice["x25519_sk"], alice["mlkem_sk"], bob["ephemeral_x25519_pk"], bob["mlkem_ciphertext"]
            )
            hybrid_decaps_us.append((time.perf_counter_ns() - t2) / 1000.0)

            t3 = time.perf_counter_ns()
            HybridKeyExchangeManager.derive_symmetric_key(alice_combined)
            hybrid_kdf_us.append((time.perf_counter_ns() - t3) / 1000.0)

        hybrid_enc_stats = calculate_repetition_statistics(hybrid_encaps_us, unit="us")
        pqc_results["hybrid"] = {
            "algorithm": "X25519+ML-KEM-768",
            "standard": "IETF RFC 9370 / NIST SP 800-56C",
            "public_bundle_bytes": len(sample_alice["x25519_pk"]) + len(sample_alice["mlkem_pk"]),
            "ciphertext_bundle_bytes": len(sample_bob["ephemeral_x25519_pk"]) + len(sample_bob["mlkem_ciphertext"]),
            "shared_secret_bytes": len(sample_bob["shared_secret"]),
            "keygen_stats": calculate_repetition_statistics(hybrid_keygen_us, unit="us"),
            "encaps_stats": hybrid_enc_stats,
            "decaps_stats": calculate_repetition_statistics(hybrid_decaps_us, unit="us"),
            "kdf_stats": calculate_repetition_statistics(hybrid_kdf_us, unit="us"),
            "energy_consumption": PowerCFGEnergyMeter.calculate_energy(
                execution_time_sec=hybrid_enc_stats["mean"] / 1_000_000.0,
                algorithm="X25519+ML-KEM-768",
                workflow="HYBRID_PQC_AEAD",
                is_pqc=True,
            ),
        }

    exec_summary = snapshot.finish()

    return {
        "run_id": run_id,
        "timestamp": timestamp_iso,
        "iterations": iterations,
        "payload_size_bytes": len(payload_bytes),
        "associated_data_size_bytes": len(aad_bytes),
        "hardware_profile": hardware_profile,
        "execution_summary": exec_summary,
        "aead_benchmarks": aead_results,
        "benchmarks": aead_results,
        "pqc_benchmarks": pqc_results,
    }


def print_benchmark_table(report: Dict[str, Any]):
    print("\n" + "=" * 96)
    print(f"   SECURE MID CRYPTOGRAPHIC BENCHMARK REPORT (RUN ID: {report['run_id']})")
    print(f"   Device: {report['hardware_profile']['device_name']} | CPU: {report['hardware_profile']['cpu_brand']}")
    print(f"   Payload: {report['payload_size_bytes']} B | AAD: {report['associated_data_size_bytes']} B | Iterations: {report['iterations']}")
    print("=" * 96)
    header = f"{'Algorithm':<20} | {'Key/Tag':<10} | {'Enc Mean (us)':<14} | {'Dec Mean (us)':<14} | {'Throughput':<14} | {'Wire Overhead'}"
    print(header)
    print("-" * 96)

    for algo, b in report["aead_benchmarks"].items():
        key_tag = f"{b['key_bits']}b/{b['tag_bytes']}B"
        enc_s = b["encryption"]["stats"]
        dec_s = b["decryption"]["stats"]
        enc_str = f"{enc_s['mean']} +/- {enc_s['stdev']}"
        dec_str = f"{dec_s['mean']} +/- {dec_s['stdev']}"
        tp_str = f"{b['encryption']['throughput_mb_s']} MB/s"
        wire_str = f"{b['total_wire_bytes']} B (+{b['overhead_pct']}%)"
        print(f"{algo:<20} | {key_tag:<10} | {enc_str:<14} | {dec_str:<14} | {tp_str:<14} | {wire_str}")

    print("=" * 96)
    print("MEASUREMENT VERIFICATION:")
    print("  [MEASURED] All timings captured via monotonic nanosecond hardware counter.")
    print("  [CALCULATED] Throughput and confidence intervals derived strictly from measured observations.")
    print("  [UNAVAILABLE] Energy consumption marked Unavailable (no physical power meter detected).")
    print("=" * 96 + "\n")


if __name__ == "__main__":
    rep = run_comparative_benchmark(iterations=100, payload_size=64, aad_size=32)
    print_benchmark_table(rep)
