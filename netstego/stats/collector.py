"""Real-time metrics collector for send/receive sessions.

Tracks packets, timestamps, and field values during transmission.
Writes to the stats database periodically.
"""

import time
import uuid
from datetime import datetime

from netstego.stats.db import PacketLog, SessionRecord, init_db


class StatsCollector:
    """Collects and persists session statistics.

    Usage:
        collector = StatsCollector(db_path="stats.db")
        sid = collector.start_session(direction="send", channel="icmp", dest_ip="10.0.0.1")
        collector.log_packet(sid, seq=0, field_name="icmp_payload", field_value="...", size=100)
        collector.finish_session(sid, status="completed")
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._session_factory = init_db(db_path)
        self._buffer: list[PacketLog] = []
        self._flush_size = 50

    def start_session(
        self,
        direction: str,
        channel: str,
        dest_ip: str | None = None,
        bind_ip: str | None = None,
        file_size: int | None = None,
        total_packets: int | None = None,
        total_chunks: int | None = None,
    ) -> str:
        """Start a new session and return its ID.

        Args:
            direction: 'send' or 'receive'.
            channel: Channel name.
            dest_ip: Destination IP (for send).
            bind_ip: Bind IP (for receive).
            file_size: Original file size in bytes.
            total_packets: Expected total packets.
            total_chunks: Expected total chunks.

        Returns:
            Session ID string.
        """
        session_id = uuid.uuid4().hex[:16]
        record = SessionRecord(
            session_id=session_id,
            direction=direction,
            channel=channel,
            dest_ip=dest_ip,
            bind_ip=bind_ip,
            file_size=file_size,
            total_packets=total_packets,
            total_chunks=total_chunks,
            started_at=datetime.utcnow(),
            status="in_progress",
        )
        with self._session_factory() as db:
            db.add(record)
            db.commit()
        return session_id

    def log_packet(
        self,
        session_id: str,
        seq: int,
        field_name: str | None = None,
        field_value: str | None = None,
        size: int | None = None,
    ) -> None:
        """Log a single packet event.

        Args:
            session_id: Session ID.
            seq: Packet sequence number.
            field_name: Name of the steganographic field.
            field_value: String value of the field.
            size: Packet size in bytes.
        """
        entry = PacketLog(
            session_id=session_id,
            seq=seq,
            timestamp=time.time(),
            field_name=field_name,
            field_value=field_value,
            packet_size=size,
        )
        self._buffer.append(entry)
        if len(self._buffer) >= self._flush_size:
            self.flush()

    def flush(self) -> None:
        """Write buffered packet logs to database."""
        if not self._buffer:
            return
        with self._session_factory() as db:
            db.add_all(self._buffer)
            db.commit()
        self._buffer.clear()

    def finish_session(
        self,
        session_id: str,
        status: str = "completed",
        total_packets: int | None = None,
    ) -> None:
        """Mark a session as finished.

        Args:
            session_id: Session ID.
            status: Final status ('completed' or 'failed').
            total_packets: Actual total packets sent/received.
        """
        self.flush()
        with self._session_factory() as db:
            record = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if record:
                record.status = status
                record.finished_at = datetime.utcnow()
                if total_packets is not None:
                    record.total_packets = total_packets
                db.commit()

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Retrieve a session record by ID."""
        with self._session_factory() as db:
            return db.query(SessionRecord).filter_by(session_id=session_id).first()

    def list_sessions(self, limit: int = 20) -> list[SessionRecord]:
        """List recent sessions."""
        with self._session_factory() as db:
            return (
                db.query(SessionRecord)
                .order_by(SessionRecord.started_at.desc())
                .limit(limit)
                .all()
            )
