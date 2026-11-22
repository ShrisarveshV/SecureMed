"""
SecureMed Protocol Packet Definition & Validation
Handles strict validation of untrusted incoming packets,
Base64 serialization/deserialization, and canonical AAD generation.
"""

import base64
import json
from typing import Dict, Any, Optional

MAX_PACKET_SIZE_BYTES = 65536  # 64 KB limit for telemetry packets
ALLOWED_ALGORITHMS = {
    "AES-128-CCM",
    "AES-256-CCM",
    "AES-128-GCM",
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "Ascon-AEAD128",
    "ML-KEM-768-AES-GCM",
    "X25519+ML-KEM-768",
}

class PacketValidationError(Exception):
    """Raised when an incoming packet violates protocol structure or constraints."""
    pass


class SecureMedPacket:
    """
    Represents a SecureMed encrypted medical telemetry packet.
    """

    def __init__(
        self,
        protocol_version: int,
        device_id: str,
        session_id: str,
        sequence_number: int,
        algorithm: str,
        nonce_b64: str,
        ciphertext_b64: str,
        authentication_tag_b64: str,
        attack_injected: Optional[str] = None
    ):
        self.protocol_version = protocol_version
        self.device_id = device_id
        self.session_id = session_id
        self.sequence_number = sequence_number
        self.algorithm = algorithm
        self.nonce_b64 = nonce_b64
        self.ciphertext_b64 = ciphertext_b64
        self.authentication_tag_b64 = authentication_tag_b64
        self.attack_injected = attack_injected

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "protocol_version": self.protocol_version,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "sequence_number": self.sequence_number,
            "algorithm": self.algorithm,
            "nonce": self.nonce_b64,
            "ciphertext": self.ciphertext_b64,
            "authentication_tag": self.authentication_tag_b64,
        }
        if self.attack_injected:
            d["attack_injected"] = self.attack_injected
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def get_canonical_aad(self) -> bytes:
        """
        Constructs canonical Authenticated Associated Data (AAD) byte string.
        Protects header fields (version, device ID, session ID, sequence number, algorithm)
        against unauthorized tampering during transit.
        """
        aad_str = (
            f"VER:{self.protocol_version}|"
            f"DEV:{self.device_id}|"
            f"SES:{self.session_id}|"
            f"SEQ:{self.sequence_number}|"
            f"ALG:{self.algorithm}"
        )
        return aad_str.encode("utf-8")

    def get_nonce_bytes(self) -> bytes:
        return base64.b64decode(self.nonce_b64)

    def get_ciphertext_bytes(self) -> bytes:
        return base64.b64decode(self.ciphertext_b64)

    def get_tag_bytes(self) -> bytes:
        return base64.b64decode(self.authentication_tag_b64)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecureMedPacket":
        """
        Strict validation of untrusted dictionary input.
        """
        if not isinstance(data, dict):
            raise PacketValidationError("Packet payload must be a JSON object")

        # 1. Check required fields
        required_fields = [
            "protocol_version",
            "device_id",
            "session_id",
            "sequence_number",
            "algorithm",
            "nonce",
            "ciphertext",
            "authentication_tag",
        ]
        for field in required_fields:
            if field not in data:
                raise PacketValidationError(f"Missing mandatory protocol field: '{field}'")

        # 2. Type and range validations
        version = data["protocol_version"]
        if not isinstance(version, int) or version != 1:
            raise PacketValidationError(f"Unsupported protocol_version: {version}. Expected 1.")

        device_id = data["device_id"]
        if not isinstance(device_id, str) or not (1 <= len(device_id) <= 64):
            raise PacketValidationError("Invalid device_id length (must be 1-64 chars)")

        session_id = data["session_id"]
        if not isinstance(session_id, str) or not (1 <= len(session_id) <= 64):
            raise PacketValidationError("Invalid session_id length (must be 1-64 chars)")

        seq = data["sequence_number"]
        if not isinstance(seq, int) or seq < 0 or seq > (2**63 - 1):
            raise PacketValidationError(f"Invalid sequence_number: {seq}")

        algo = data["algorithm"]
        if algo not in ALLOWED_ALGORITHMS:
            raise PacketValidationError(f"Unsupported algorithm '{algo}'. Allowed: {ALLOWED_ALGORITHMS}")

        # 3. Validate Base64 encodings and lengths
        for b64_field in ["nonce", "ciphertext", "authentication_tag"]:
            val = data[b64_field]
            if not isinstance(val, str):
                raise PacketValidationError(f"Field '{b64_field}' must be a base64 encoded string")
            try:
                raw_bytes = base64.b64decode(val, validate=True)
            except Exception as e:
                raise PacketValidationError(f"Field '{b64_field}' has invalid base64 encoding: {e}")

            # Specific length checks
            if b64_field == "authentication_tag" and len(raw_bytes) != 16:
                raise PacketValidationError(
                    f"Authentication tag length must be exactly 16 bytes (got {len(raw_bytes)})"
                )
            if b64_field == "nonce" and len(raw_bytes) not in (12, 13, 16):
                raise PacketValidationError(
                    f"Nonce length must be 12, 13, or 16 bytes (got {len(raw_bytes)})"
                )

        return cls(
            protocol_version=version,
            device_id=device_id,
            session_id=session_id,
            sequence_number=seq,
            algorithm=algo,
            nonce_b64=data["nonce"],
            ciphertext_b64=data["ciphertext"],
            authentication_tag_b64=data["authentication_tag"],
            attack_injected=data.get("attack_injected")
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SecureMedPacket":
        if len(json_str) > MAX_PACKET_SIZE_BYTES:
            raise PacketValidationError(
                f"Packet exceeds maximum allowed size ({len(json_str)} > {MAX_PACKET_SIZE_BYTES} bytes)"
            )
        try:
            data = json.loads(json_str)
        except Exception as e:
            raise PacketValidationError(f"Malformed JSON packet: {e}")
        return cls.from_dict(data)
