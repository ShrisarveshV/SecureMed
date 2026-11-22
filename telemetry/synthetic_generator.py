"""
SecureMed Synthetic Medical Telemetry Generator
Generates realistic clinical telemetry for educational cybersecurity testing:
  1. Pacemaker (SIM-PM-001)
  2. Implantable Cardioverter-Defibrillator / ICD (SIM-ICD-002)
  3. Continuous Glucose Monitor / CGM (SIM-CGM-003)
  4. Wearable ECG Monitor (SIM-ECG-004)

All telemetry is explicitly flagged as synthetic.
DO NOT use with real clinical medical devices.
"""

import math
import random
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

class SyntheticTelemetryGenerator:
    """
    Stateful generator for continuous physiological telemetry simulations.
    """

    def __init__(self, device_type: str = "pacemaker", device_id: str = "SIM-PM-001"):
        self.device_type = device_type.lower()
        self.device_id = device_id
        self.step_counter = 0

        # Baseline physiological parameters
        self.heart_rate = 72.0
        self.glucose = 108.0
        self.battery_level_pct = 98.5
        self.lead_impedance = 520.0

    def generate_packet_data(self, sequence_number: int, session_id: str) -> Dict[str, Any]:
        """
        Produces the payload to be encrypted.
        """
        self.step_counter += 1
        now_iso = datetime.now(timezone.utc).isoformat()

        if self.device_type == "pacemaker":
            return self._generate_pacemaker(sequence_number, session_id, now_iso)
        elif self.device_type in ("icd", "defibrillator"):
            return self._generate_icd(sequence_number, session_id, now_iso)
        elif self.device_type == "cgm":
            return self._generate_cgm(sequence_number, session_id, now_iso)
        elif self.device_type in ("ecg", "wearable_ecg"):
            return self._generate_ecg(sequence_number, session_id, now_iso)
        else:
            return self._generate_pacemaker(sequence_number, session_id, now_iso)

    def _generate_pacemaker(self, seq: int, session_id: str, ts: str) -> Dict[str, Any]:
        # Slight physiological sinus respiratory fluctuation
        fluctuation = 2.5 * math.sin(self.step_counter * 0.2) + random.uniform(-0.8, 0.8)
        self.heart_rate = round(max(55.0, min(100.0, 72.0 + fluctuation)), 1)
        self.battery_level_pct = max(10.0, round(self.battery_level_pct - 0.0002, 3))
        self.lead_impedance = round(self.lead_impedance + random.uniform(-1.0, 1.0), 1)

        status = "NORMAL"
        if self.heart_rate < 60:
            status = "PACING_ACTIVE"

        return {
            "synthetic": True,
            "device_id": self.device_id or "SIM-PM-001",
            "device_type": "Pacemaker",
            "session_id": session_id,
            "sequence_number": seq,
            "timestamp": ts,
            "heart_rate_bpm": self.heart_rate,
            "pacing_mode": "DDDR",
            "pacing_pulse_v": 2.5,
            "pulse_width_ms": 0.4,
            "lead_impedance_ohms": self.lead_impedance,
            "battery_percent": self.battery_level_pct,
            "device_status": status,
        }

    def _generate_icd(self, seq: int, session_id: str, ts: str) -> Dict[str, Any]:
        fluctuation = 3.0 * math.sin(self.step_counter * 0.15) + random.uniform(-1.0, 1.0)
        vent_rate = round(max(58.0, min(110.0, 75.0 + fluctuation)), 1)

        return {
            "synthetic": True,
            "device_id": self.device_id or "SIM-ICD-002",
            "device_type": "ICD",
            "session_id": session_id,
            "sequence_number": seq,
            "timestamp": ts,
            "ventricular_rate_bpm": vent_rate,
            "sensing_amplitude_mv": round(12.0 + random.uniform(-0.5, 0.5), 2),
            "shock_capacitor_voltage_v": 750,
            "shocks_delivered_lifetime": 0,
            "tachycardia_zone_threshold_bpm": 180,
            "vfib_detected": False,
            "device_status": "MONITORING_SECURE",
        }

    def _generate_cgm(self, seq: int, session_id: str, ts: str) -> Dict[str, Any]:
        # Realistic smooth random walk for blood glucose
        drift = random.uniform(-1.5, 1.6)
        self.glucose = round(max(70.0, min(180.0, self.glucose + drift)), 1)

        if drift > 0.8:
            trend = "RISING"
        elif drift < -0.8:
            trend = "FALLING"
        else:
            trend = "STABLE"

        return {
            "synthetic": True,
            "device_id": self.device_id or "SIM-CGM-003",
            "device_type": "Continuous Glucose Monitor",
            "session_id": session_id,
            "sequence_number": seq,
            "timestamp": ts,
            "glucose_mg_dl": self.glucose,
            "trend": trend,
            "rate_of_change_mg_dl_min": round(drift * 0.5, 2),
            "sensor_current_na": round(24.0 + (self.glucose - 100) * 0.12, 2),
            "calibration_status": "VERIFIED_VALID",
            "device_status": "NORMAL",
        }

    def _generate_ecg(self, seq: int, session_id: str, ts: str) -> Dict[str, Any]:
        # Generate a mini 20-point realistic P-Q-R-S-T synthetic cardiac waveform
        t_cycle = (self.step_counter % 20) / 20.0
        # Synthetic ECG lead II model
        if 0.10 <= t_cycle <= 0.20:
            ecg_mv = 0.15 * math.sin((t_cycle - 0.10) / 0.10 * math.pi)  # P wave
        elif 0.35 <= t_cycle < 0.38:
            ecg_mv = -0.15  # Q wave
        elif 0.38 <= t_cycle < 0.44:
            ecg_mv = 1.25  # R peak
        elif 0.44 <= t_cycle < 0.48:
            ecg_mv = -0.30  # S wave
        elif 0.58 <= t_cycle <= 0.78:
            ecg_mv = 0.25 * math.sin((t_cycle - 0.58) / 0.20 * math.pi)  # T wave
        else:
            ecg_mv = 0.0 + random.uniform(-0.02, 0.02)  # Isoelectric baseline

        return {
            "synthetic": True,
            "device_id": self.device_id or "SIM-ECG-004",
            "device_type": "Wearable ECG Monitor",
            "session_id": session_id,
            "sequence_number": seq,
            "timestamp": ts,
            "lead": "Lead-II",
            "heart_rate_bpm": 72 + int(3 * math.sin(self.step_counter * 0.1)),
            "qrs_duration_ms": 86,
            "pr_interval_ms": 150,
            "qt_interval_ms": 385,
            "st_elevation_mm": 0.02,
            "waveform_sample_mv": round(ecg_mv, 3),
            "arrhythmia_detected": False,
            "device_status": "RHYTHM_NORMAL",
        }
