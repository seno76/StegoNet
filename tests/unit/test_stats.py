"""Unit tests for stats modules (db, collector, reporter)."""

from pathlib import Path

import pytest

from netstego.stats.db import SessionRecord, PacketLog, AnomalyScore, init_db
from netstego.stats.collector import StatsCollector


class TestDatabase:
    def test_init_creates_tables(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        factory = init_db(db_path)
        assert db_path.exists()
        with factory() as session:
            # Should not raise — tables exist
            session.query(SessionRecord).count()
            session.query(PacketLog).count()
            session.query(AnomalyScore).count()

    def test_insert_session(self, tmp_path: Path) -> None:
        factory = init_db(tmp_path / "test.db")
        with factory() as session:
            record = SessionRecord(
                session_id="test123",
                direction="send",
                channel="icmp",
                dest_ip="10.0.0.1",
                file_size=1024,
                status="completed",
            )
            session.add(record)
            session.commit()
            result = session.query(SessionRecord).filter_by(session_id="test123").first()
            assert result is not None
            assert result.channel == "icmp"
            assert result.file_size == 1024


class TestCollector:
    def test_start_and_finish_session(self, tmp_path: Path) -> None:
        collector = StatsCollector(db_path=str(tmp_path / "stats.db"))
        sid = collector.start_session(
            direction="send",
            channel="icmp",
            dest_ip="10.0.0.1",
            file_size=512,
        )
        assert len(sid) == 16

        collector.log_packet(sid, seq=0, field_name="icmp_payload", field_value="data", size=100)
        collector.log_packet(sid, seq=1, field_name="icmp_payload", field_value="data2", size=100)
        collector.finish_session(sid, status="completed", total_packets=2)

        record = collector.get_session(sid)
        assert record is not None
        assert record.status == "completed"
        assert record.total_packets == 2

    def test_list_sessions(self, tmp_path: Path) -> None:
        collector = StatsCollector(db_path=str(tmp_path / "stats.db"))
        sid1 = collector.start_session(direction="send", channel="icmp")
        sid2 = collector.start_session(direction="receive", channel="ip-id")
        collector.finish_session(sid1)
        collector.finish_session(sid2)

        sessions = collector.list_sessions()
        assert len(sessions) == 2

    def test_flush_buffered_packets(self, tmp_path: Path) -> None:
        collector = StatsCollector(db_path=str(tmp_path / "stats.db"))
        collector._flush_size = 5  # Lower threshold for test
        sid = collector.start_session(direction="send", channel="icmp")

        for i in range(10):
            collector.log_packet(sid, seq=i, size=64)

        # Should have auto-flushed at least once
        collector.flush()  # Flush remaining
        factory = init_db(str(tmp_path / "stats.db"))
        with factory() as session:
            count = session.query(PacketLog).filter_by(session_id=sid).count()
            assert count == 10
