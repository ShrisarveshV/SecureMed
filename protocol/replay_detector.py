"""
SecureMed Replay Protection Engine
Implements anti-replay protection using sequence numbers,
session-binding, and a sliding bitmap window (RFC 4303 IPsec style).
"""

from typing import Tuple, Dict, Set, Optional, Any

DEFAULT_WINDOW_SIZE = 64  # Sliding window size for out-of-order tolerance

class ReplayCheckResult:
    ACCEPTED = "ACCEPTED"
    REPLAY_DUPLICATE = "REPLAY_DUPLICATE"
    REPLAY_STALE = "REPLAY_STALE"
    INVALID_SESSION = "INVALID_SESSION"
    SEQUENCE_REGRESSION = "SEQUENCE_REGRESSION"

class ReplayDetector:
    """
    Session-aware replay detector for medical telemetry streams.
    Tracks sequence numbers and maintains a sliding window of accepted packets.
    """

    def __init__(self, window_size: int = DEFAULT_WINDOW_SIZE):
        self.window_size = window_size
        self.active_session_id: Optional[str] = None
        self.highest_sequence: int = -1
        # Set of sequence numbers received within the window [highest_seq - window_size + 1, highest_seq]
        self.received_in_window: Set[int] = set()
        self.total_accepted: int = 0
        self.total_replays_detected: int = 0

    def get_window_state(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns the current state of the sliding window for inspection/debugging."""
        target_session = session_id or self.active_session_id
        window_low = max(0, self.highest_sequence - self.window_size + 1) if self.highest_sequence >= 0 else 0
        window_high = self.highest_sequence if self.highest_sequence >= 0 else 0
        return {
            "session_id": target_session,
            "highest_sequence": self.highest_sequence,
            "window_low": window_low,
            "window_high": window_high,
            "window_size": self.window_size,
            "received_count": len(self.received_in_window),
            "received_sequences": sorted(self.received_in_window),
            "total_accepted": self.total_accepted,
            "total_replays_detected": self.total_replays_detected,
        }

    def reset_session(self, session_id: str) -> None:
        """Initialize or reset state for a new session."""
        self.active_session_id = session_id
        self.highest_sequence = -1
        self.received_in_window.clear()

    def check_and_update(self, session_id: str, sequence_number: int) -> Tuple[bool, str]:
        """
        Validates whether the packet is fresh and legitimate.
        Returns: (is_accepted: bool, status_reason: str)
        """
        # 1. Session verification
        if self.active_session_id is None:
            self.active_session_id = session_id

        if session_id != self.active_session_id:
            # Different session must undergo session establishment
            return False, f"Rejection: Packet session '{session_id}' does not match active session '{self.active_session_id}'"

        # First packet in session
        if self.highest_sequence == -1:
            self.highest_sequence = sequence_number
            self.received_in_window.add(sequence_number)
            self.total_accepted += 1
            return True, ReplayCheckResult.ACCEPTED

        # 2. Duplicate check within sliding window
        if sequence_number in self.received_in_window:
            self.total_replays_detected += 1
            return False, f"Replay Detected: Duplicate sequence number {sequence_number} already accepted"

        # 3. Packet is newer than the highest seen sequence
        if sequence_number > self.highest_sequence:
            diff = sequence_number - self.highest_sequence
            self.highest_sequence = sequence_number
            self.received_in_window.add(sequence_number)

            # Evict entries that fell behind the window
            cutoff = self.highest_sequence - self.window_size
            self.received_in_window = {seq for seq in self.received_in_window if seq > cutoff}
            self.total_accepted += 1
            return True, ReplayCheckResult.ACCEPTED

        # 4. Packet is older than highest, but within the sliding window
        diff = self.highest_sequence - sequence_number
        if diff < self.window_size:
            # Not a duplicate (checked above), so it's a tolerated out-of-order packet
            self.received_in_window.add(sequence_number)
            self.total_accepted += 1
            return True, f"ACCEPTED (Out-of-order, delta=-{diff})"

        # 5. Packet is too old (fell outside the sliding window)
        self.total_replays_detected += 1
        return False, (
            f"Replay Detected: Stale sequence number {sequence_number} "
            f"fell outside window [{self.highest_sequence - self.window_size + 1}, {self.highest_sequence}]"
        )
