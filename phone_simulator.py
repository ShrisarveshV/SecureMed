"""
SecureMed Standalone Simulated Medical Device (Phone / Client CLI)
Can be run on Android via Termux, on another laptop/phone on Wi-Fi, or locally.
Simulates:
  - Pacemaker (SIM-PM-001)
  - ICD Defibrillator (SIM-ICD-002)
  - Continuous Glucose Monitor / CGM (SIM-CGM-003)
  - Wearable ECG Monitor (SIM-ECG-004)

Performs local client-side authenticated encryption and transmits strictly
encrypted packets over Wi-Fi (HTTP or WebSocket) to the laptop receiver.
Derives keys using HKDF-SHA256 from out-of-band pairing token or ML-KEM-768.
The encryption key is NEVER transmitted in plaintext.
"""

import sys
import time
import json
import base64
import argparse
import requests

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from crypto_engine.ciphers import (
    SecureMedCryptoEngine,
    PostQuantumKEMManager,
    SUPPORTED_ALGORITHMS,
)
from telemetry.synthetic_generator import SyntheticTelemetryGenerator
from protocol.packet import SecureMedPacket


def derive_session_key_from_token(pairing_token: str, session_id: str, algorithm: str) -> bytes:
    """
    Derives symmetric session key using HKDF-SHA256 (NIST SP 800-56C).
    Raw cryptographic key is never sent over the wire.
    """
    key_length = 32 if algorithm in ("AES-256-GCM", "AES-256-CCM", "ChaCha20-Poly1305", "ML-KEM-768-AES-GCM", "X25519+ML-KEM-768") else 16
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=session_id.encode("utf-8"),
        info=f"SecureMed-SessionKey-{algorithm}".encode("utf-8"),
    )
    return hkdf.derive(pairing_token.encode("utf-8"))


def run_simulator(
    receiver_url: str,
    device_type: str = "pacemaker",
    algorithm: str = "AES-128-CCM",
    interval_sec: float = 1.0,
    max_packets: int = 50,
    simulate_attacks: bool = False,
    pairing_token_arg: str = ""
):
    print("=" * 65)
    print("  [+] SECUREMED: SIMULATED MEDICAL DEVICE (PHONE CLIENT)")
    print("=" * 65)
    print(f"[*] Target Receiver: {receiver_url}")
    print(f"[*] Device Type:     {device_type.upper()}")
    print(f"[*] Algorithm:       {algorithm}")
    print(f"[*] Interval:        {interval_sec} s")
    print("=" * 65)

    # 1. Fetch Session Info & Out-of-band Pairing Token
    session_info_url = f"{receiver_url}/api/session_info"
    session_data = {}
    try:
        resp = requests.get(session_info_url, timeout=5)
        resp.raise_for_status()
        session_data = resp.json()
        session_id = session_data["session_id"]
        server_algo = session_data.get("algorithm", algorithm)
        pairing_token = pairing_token_arg or session_data.get("pairing_token") or "SecureMedBootstrapDefault"
        print(f"[+] Handshake OK. Active Session: {session_id}")
    except Exception as e:
        print(f"[!] Could not connect to receiver at {receiver_url}: {e}")
        print("[!] Operating in local autonomous test mode.")
        session_id = f"SES-LOCAL-{int(time.time())}"
        pairing_token = pairing_token_arg or "SecureMedLocalTestToken"

    # If Post-Quantum ML-KEM-768 requested
    if algorithm == "ML-KEM-768-AES-GCM" and "kem_public_key_b64" in session_data:
        print("[*] Performing Post-Quantum ML-KEM-768 Key Encapsulation...")
        receiver_pk = base64.b64decode(session_data["kem_public_key_b64"])
        shared_secret, kem_ct = PostQuantumKEMManager.encapsulate(receiver_pk)
        # Negotiate session with receiver
        neg_resp = requests.post(
            f"{receiver_url}/api/negotiate_session",
            json={
                "algorithm": algorithm,
                "client_kem_ciphertext_b64": base64.b64encode(kem_ct).decode("utf-8")
            }
        )
        neg_data = neg_resp.json()
        session_id = neg_data["session_id"]
        server_key = PostQuantumKEMManager.derive_session_key(shared_secret, salt=session_id.encode())
        print(f"[+] Post-Quantum ML-KEM-768 Session Established ({session_id}).")
    else:
        # If client algorithm differs from server, request negotiation
        if session_data and algorithm != session_data.get("algorithm"):
            try:
                neg_resp = requests.post(
                    f"{receiver_url}/api/negotiate_session",
                    json={"algorithm": algorithm, "pairing_token": pairing_token}
                )
                neg_data = neg_resp.json()
                session_id = neg_data["session_id"]
            except Exception:
                pass
        # Derive symmetric key locally from pairing token (NO KEY TRANSMITTED OVER WIRE)
        server_key = derive_session_key_from_token(pairing_token, session_id, algorithm)
        print(f"[+] Symmetric key derived via HKDF-SHA256 ({len(server_key)*8} bits).")

    # 2. Setup Generator & Crypto Engine
    device_id_map = {
        "pacemaker": "SIM-PM-001",
        "icd": "SIM-ICD-002",
        "cgm": "SIM-CGM-003",
        "ecg": "SIM-ECG-004",
    }
    device_id = device_id_map.get(device_type.lower(), "SIM-PM-001")
    generator = SyntheticTelemetryGenerator(device_type=device_type, device_id=device_id)
    engine = SecureMedCryptoEngine(key=server_key, algorithm=algorithm)

    seq = 1
    last_packet_dict = None

    for i in range(max_packets):
        # Generate Synthetic Telemetry
        telemetry_dict = generator.generate_packet_data(seq, session_id)
        plaintext_bytes = json.dumps(telemetry_dict).encode("utf-8")

        # Canonical AAD protects header fields against tampering
        aad_str = f"VER:1|DEV:{device_id}|SES:{session_id}|SEQ:{seq}|ALG:{algorithm}"
        aad_bytes = aad_str.encode("utf-8")

        # Local Hardware/Software Authenticated Encryption
        ct_bytes, nonce_bytes, tag_bytes, enc_time_ms = engine.encrypt(
            plaintext=plaintext_bytes,
            associated_data=aad_bytes,
            algorithm=algorithm
        )

        packet = SecureMedPacket(
            protocol_version=1,
            device_id=device_id,
            session_id=session_id,
            sequence_number=seq,
            algorithm=algorithm,
            nonce_b64=base64.b64encode(nonce_bytes).decode("utf-8"),
            ciphertext_b64=base64.b64encode(ct_bytes).decode("utf-8"),
            authentication_tag_b64=base64.b64encode(tag_bytes).decode("utf-8"),
        )
        packet_dict = packet.to_dict()

        # Controlled Attack Injection
        attack_desc = "NORMAL"
        if simulate_attacks:
            if i == 5:
                # Tamper ciphertext
                attack_desc = "TAMPER_CIPHERTEXT"
                raw_ct = bytearray(ct_bytes)
                raw_ct[0] ^= 0xFF
                packet_dict["ciphertext"] = base64.b64encode(raw_ct).decode("utf-8")
                packet_dict["attack_injected"] = "TAMPER_CIPHERTEXT"
            elif i == 10:
                # Replay previous packet
                attack_desc = "REPLAY_PACKET"
                if last_packet_dict:
                    packet_dict = dict(last_packet_dict)
                    packet_dict["attack_injected"] = "REPLAY_PACKET"
            elif i == 15:
                # Tamper tag
                attack_desc = "TAMPER_TAG"
                raw_tag = bytearray(tag_bytes)
                raw_tag[-1] ^= 0x01
                packet_dict["authentication_tag"] = base64.b64encode(raw_tag).decode("utf-8")
                packet_dict["attack_injected"] = "TAMPER_TAG"

        last_packet_dict = dict(packet_dict)

        # Transmit to Laptop Receiver
        try:
            post_resp = requests.post(
                f"{receiver_url}/api/process_packet",
                json=packet_dict,
                timeout=3
            )
            res_data = post_resp.json()
            status = res_data.get("status", "UNKNOWN")
            dec_time = res_data.get("decryption_time_ms", 0.0)
            reason = res_data.get("rejection_reason", "")
            print(
                f"[{i+1:02d}] Seq #{seq:03d} | Enc: {enc_time_ms:.2f}ms | "
                f"Dec: {dec_time:.2f}ms | Status: {status:<22} | Attack: {attack_desc}"
            )
            if reason:
                print(f"     |--> Receiver Decision: {reason}")
        except Exception as e:
            print(f"[{i+1:02d}] Seq #{seq:03d} | Network Error: {e}")

        seq += 1
        time.sleep(interval_sec)

    print("\n[+] Simulation run complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureMed Phone Simulator CLI")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Laptop Receiver URL")
    parser.add_argument("--device", default="pacemaker", choices=["pacemaker", "icd", "cgm", "ecg"], help="Device type")
    parser.add_argument("--algo", default="AES-128-CCM", choices=SUPPORTED_ALGORITHMS, help="AEAD algorithm")
    parser.add_argument("--interval", type=float, default=0.5, help="Interval in seconds")
    parser.add_argument("--count", type=int, default=20, help="Packet count")
    parser.add_argument("--attacks", action="store_true", help="Inject controlled tamper & replay attacks")
    parser.add_argument("--token", default="", help="Out-of-band pairing token / PIN")
    args = parser.parse_args()

    run_simulator(
        receiver_url=args.url,
        device_type=args.device,
        algorithm=args.algo,
        interval_sec=args.interval,
        max_packets=args.count,
        simulate_attacks=args.attacks,
        pairing_token_arg=args.token,
    )
