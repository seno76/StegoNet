"""SQLAlchemy ORM models for NetStego statistics database.

Tables:
    - sessions: Metadata for each send/receive session
    - packets_log: Per-packet log with timestamps and field values
    - anomaly_scores: Detection results per analysis run
"""

from datetime import datetime
from pathlib import Path

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class SessionRecord(Base):
    """A transmission or reception session."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    direction = Column(String(10), nullable=False)  # 'send' or 'receive'
    channel = Column(String(20), nullable=False)
    dest_ip = Column(String(45))
    bind_ip = Column(String(45))
    file_size = Column(Integer)
    total_packets = Column(Integer)
    total_chunks = Column(Integer)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    status = Column(String(20), default="in_progress")  # in_progress, completed, failed


class PacketLog(Base):
    """Per-packet log entry."""

    __tablename__ = "packets_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    timestamp = Column(Float, nullable=False)  # epoch seconds
    field_name = Column(String(30))  # e.g., 'ip_id', 'tcp_seq', 'icmp_payload'
    field_value = Column(Text)  # string representation of the value
    packet_size = Column(Integer)


class AnomalyScore(Base):
    """Detection anomaly score for an analysis run."""

    __tablename__ = "anomaly_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), index=True)
    method = Column(String(30), nullable=False)  # 'chi_squared', 'ks_test', 'entropy', 'ml'
    metric_name = Column(String(50), nullable=False)
    score = Column(Float, nullable=False)
    threshold = Column(Float)
    is_anomaly = Column(Integer, default=0)  # 0 or 1
    analyzed_at = Column(DateTime, default=datetime.utcnow)
    details = Column(Text)  # JSON details


def get_engine(db_path: str | Path | None = None):
    """Create SQLAlchemy engine for the stats database.

    Args:
        db_path: Path to SQLite database. Defaults to ~/.netstego/stats.db.

    Returns:
        SQLAlchemy Engine instance.
    """
    if db_path is None:
        db_path = Path.home() / ".netstego" / "stats.db"
    else:
        db_path = Path(db_path).expanduser()

    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{db_path}")


def init_db(db_path: str | Path | None = None) -> sessionmaker:
    """Initialize database and return a session factory.

    Creates all tables if they don't exist.

    Args:
        db_path: Path to SQLite database.

    Returns:
        SQLAlchemy sessionmaker.
    """
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)
