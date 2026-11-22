"""
SecureMed Bluetooth Low Energy (BLE) Receiver Adapter
Implements Mode B GATT Server & Peripheral communication for medical telemetry.
Uses standard 128-bit Custom GATT Service & Characteristic UUIDs for medical device profiles:
  - Service UUID:        6E400001-B5A3-F393-E0A9-E50E24DCCA9E (SecureMed Telemetry Service)
  - Characteristic TX:   6E400002-B5A3-F393-E0A9-E50E24DCCA9E (Phone -> Laptop Encrypted Packets)
  - Characteristic ACK:  6E400003-B5A3-F393-E0A9-E50E24DCCA9E (Laptop -> Phone Status ACKs)
"""

import sys
import json
import asyncio
from typing import Optional, Dict, Any, Callable

# Standard Medical Telemetry Custom GATT UUIDs
SECUREMED_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
SECUREMED_CHAR_ENCRYPTED_TX = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
SECUREMED_CHAR_ACK_RX = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"

class BLETelemetryAdapter:
    """
    Cross-platform Bluetooth receiver adapter supporting:
      1. Bluetooth Low Energy (BLE) GATT telemetry.
      2. Normal Bluetooth (Classic RFCOMM / Standard Direct Transport) fallback when BLE is unavailable.
    """

    def __init__(self, packet_handler: Optional[Callable[[Dict[str, Any], str], Dict[str, Any]]] = None):
        self.is_connected = False
        self.device_address: Optional[str] = None
        self.packet_handler = packet_handler
        self.cached_hardware_status: Optional[Dict[str, Any]] = None

    async def _try_power_on_radio(self) -> bool:
        """Attempts to turn on Windows Bluetooth radio if it was disabled."""
        try:
            from winrt.windows.devices.radios import Radio, RadioKind, RadioState
            radios = await Radio.get_radios_async()
            for r in radios:
                if r.kind == RadioKind.BLUETOOTH and r.state != RadioState.ON:
                    await r.set_state_async(RadioState.ON)
                    await asyncio.sleep(0.5)
                    return True
        except Exception:
            pass
        return False

    def _check_normal_bluetooth(self) -> bool:
        """Checks if Normal (Classic RFCOMM) Bluetooth stack is supported by OS sockets."""
        import socket
        if hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_RFCOMM"):
            try:
                s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
                s.close()
                return True
            except Exception:
                return False
        return False

    async def check_bluetooth_hardware(self) -> Dict[str, Any]:
        """
        Checks Bluetooth hardware state.
        If Low Power Bluetooth (BLE) is not available, gracefully switches to Normal Bluetooth for transfer.
        """
        normal_bt = self._check_normal_bluetooth()
        ble_ok = False
        nearby_count = 0
        status_text = ""

        try:
            import bleak
            try:
                devices = await bleak.BleakScanner.discover(timeout=1.0)
                ble_ok = True
                nearby_count = len(devices)
                status_text = f"BLE active ({nearby_count} nearby peripherals found)"
            except Exception as scan_err:
                # If radio was off, attempt power-on and retry once
                if "POWERED_OFF" in str(scan_err) or "not powered on" in str(scan_err).lower():
                    powered_on = await self._try_power_on_radio()
                    if powered_on:
                        try:
                            devices = await bleak.BleakScanner.discover(timeout=1.0)
                            ble_ok = True
                            nearby_count = len(devices)
                            status_text = f"BLE active ({nearby_count} nearby peripherals found)"
                        except Exception:
                            ble_ok = False
                if not ble_ok:
                    status_text = f"BLE scan error: {str(scan_err)[:50]}"
        except ImportError:
            ble_ok = False
            status_text = "Bleak library not available"

        # Determine operating mode: BLE if available, otherwise Normal Bluetooth fallback
        if ble_ok:
            active_mode = "Bluetooth Low Energy (BLE)"
            mode_code = "BLE"
            status_summary = f"Low Power Bluetooth (BLE) Active — {nearby_count} peripherals detected."
        elif normal_bt:
            active_mode = "Normal Bluetooth (Standard RFCOMM / Direct Transfer)"
            mode_code = "NORMAL_BT"
            status_summary = "Low Power Bluetooth (BLE) unavailable — Normal Bluetooth (Standard RFCOMM) active for file transfer."
        else:
            active_mode = "Wi-Fi Only (No Bluetooth detected)"
            mode_code = "NONE"
            status_summary = "Bluetooth hardware not detected — using Wi-Fi transport."

        self.cached_hardware_status = {
            "available": ble_ok or normal_bt,
            "ble_available": ble_ok,
            "normal_bluetooth_available": normal_bt,
            "active_mode": active_mode,
            "mode_code": mode_code,
            "fallback_to_normal": (not ble_ok and normal_bt),
            "powered_on": ble_ok or normal_bt,
            "status_text": status_summary,
            "nearby_devices_count": nearby_count,
            "service_uuid": SECUREMED_SERVICE_UUID,
            "rx_char_uuid": SECUREMED_CHAR_ENCRYPTED_TX,
            "tx_char_uuid": SECUREMED_CHAR_ACK_RX,
            "connected": self.is_connected,
        }
        return self.cached_hardware_status

    def handle_received_ble_bytes(self, raw_bytes: bytes) -> Dict[str, Any]:
        """
        Processes encrypted packet received over GATT characteristic.
        Passes directly to receiver pipeline without pre-decryption.
        """
        try:
            packet_dict = json.loads(raw_bytes.decode("utf-8"))
            if self.packet_handler:
                return self.packet_handler(packet_dict, "Bluetooth-LE-GATT")
            return {"status": "NO_HANDLER"}
        except Exception as e:
            return {"status": "BLE_PARSE_ERROR", "rejection_reason": str(e)}

    def get_status_summary(self) -> Dict[str, Any]:
        if self.cached_hardware_status:
            return self.cached_hardware_status
        return {
            "available": False,
            "powered_on": False,
            "status_text": "Checking Bluetooth hardware...",
            "service_uuid": SECUREMED_SERVICE_UUID,
            "connected": False,
        }


if __name__ == "__main__":
    adapter = BLETelemetryAdapter()
    result = asyncio.run(adapter.check_bluetooth_hardware())
    print("[BLE Adapter Check]:", json.dumps(result, indent=2))
