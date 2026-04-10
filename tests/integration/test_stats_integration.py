"""Integration tests for StatsCollector integration in sender and receiver.

Tests that send/receive via PCAP pipeline correctly logs sessions and packets
to the stats database.
"""

from pathlib import Path

import pytest

from netstego.cli import cli
from netstego.core.crypto import encrypt, generate_key, load_key
from netstego.core.fragmentation import fragment
from netstego.network.receiver import receive_file
from netstego.network.sender import frame_chunks, get_channel
from netstego.stats.collector import StatsCollector
from netstego.stats.db import PacketLog, SessionRecord, init_db
from scapy.utils import wrpcap
from click.testing import CliRunner


@pytest.fixture
def setup(tmp_path: Path) -> dict:
    """Create test key, file, and PCAP for pipeline tests."""
    key_path = tmp_path / "test.key"
    key = generate_key(key_path)

    plaintext = b"Hello, StatsCollector integration test! " * 5
    file_path = tmp_path / "secret.txt"
    file_path.write_bytes(plaintext)

    db_path = str(tmp_path / "stats.db")
    pcap_path = str(tmp_path / "stego.pcap")

    return {
        "key_path": key_path,
        "key": key,
        "plaintext": plaintext,
        "file_path": file_path,
        "db_path": db_path,
        "pcap_path": pcap_path,
        "tmp_path": tmp_path,
    }


def _create_stego_pcap(setup: dict, channel_name: str) -> str:
    """Helper: create a PCAP with stego data for a given channel."""
    key = load_key(setup["key_path"])
    ciphertext = encrypt(setup["plaintext"], key)
    channel = get_channel(channel_name)
    bytes_per_packet = channel.bits_per_packet // 8
    overhead = 17 + 4
    chunk_data_size = (bytes_per_packet - overhead) if bytes_per_packet > overhead + 33 else 128
    chunks = fragment(ciphertext, chunk_data_size)
    framed = frame_chunks(chunks)
    packets = channel.encode(framed, dest_ip="10.0.0.2")
    wrpcap(setup["pcap_path"], packets)
    return setup["pcap_path"]


class TestReceiverStatsIntegration:
    """Test that receive_file logs sessions and packets to stats DB."""

    def test_receive_creates_session(self, setup: dict) -> None:
        pcap = _create_stego_pcap(setup, "icmp")
        output = setup["tmp_path"] / "recovered.txt"

        success = receive_file(
            sender_ip="10.0.0.1",
            key_path=setup["key_path"],
            output_path=output,
            channel_name="icmp",
            pcap_in=Path(pcap),
            db_path=setup["db_path"],
        )
        assert success

        # Verify session was created in DB
        factory = init_db(setup["db_path"])
        with factory() as db:
            sessions = db.query(SessionRecord).all()
            assert len(sessions) == 1
            s = sessions[0]
            assert s.direction == "receive"
            assert s.channel == "icmp"
            assert s.status == "completed"

    def test_receive_logs_packets(self, setup: dict) -> None:
        pcap = _create_stego_pcap(setup, "icmp")
        output = setup["tmp_path"] / "recovered.txt"

        receive_file(
            sender_ip="10.0.0.1",
            key_path=setup["key_path"],
            output_path=output,
            channel_name="icmp",
            pcap_in=Path(pcap),
            db_path=setup["db_path"],
        )

        factory = init_db(setup["db_path"])
        with factory() as db:
            sessions = db.query(SessionRecord).all()
            sid = sessions[0].session_id
            packets = db.query(PacketLog).filter_by(session_id=sid).all()
            assert len(packets) > 0

    def test_receive_failed_status_on_bad_key(self, setup: dict) -> None:
        pcap = _create_stego_pcap(setup, "icmp")
        output = setup["tmp_path"] / "recovered.txt"

        # Use a different key to cause decryption failure
        wrong_key_path = setup["tmp_path"] / "wrong.key"
        generate_key(wrong_key_path)

        success = receive_file(
            sender_ip="10.0.0.1",
            key_path=wrong_key_path,
            output_path=output,
            channel_name="icmp",
            pcap_in=Path(pcap),
            db_path=setup["db_path"],
        )
        assert success is False

        factory = init_db(setup["db_path"])
        with factory() as db:
            sessions = db.query(SessionRecord).all()
            assert len(sessions) == 1
            assert sessions[0].status == "failed"

    def test_receive_all_channels(self, setup: dict) -> None:
        """Test stats integration for all 5 channels."""
        for ch in ["icmp", "ip-id", "tcp-isn", "dns", "tcp-ts"]:
            db_path = str(setup["tmp_path"] / f"stats_{ch}.db")
            pcap = _create_stego_pcap(setup, ch)
            output = setup["tmp_path"] / f"recovered_{ch}.txt"

            success = receive_file(
                sender_ip="10.0.0.1",
                key_path=setup["key_path"],
                output_path=output,
                channel_name=ch,
                pcap_in=Path(pcap),
                db_path=db_path,
            )
            assert success, f"Failed for channel {ch}"

            factory = init_db(db_path)
            with factory() as db:
                sessions = db.query(SessionRecord).all()
                assert len(sessions) == 1
                assert sessions[0].status == "completed"
                assert sessions[0].channel == ch

                packets = db.query(PacketLog).filter_by(session_id=sessions[0].session_id).all()
                assert len(packets) > 0

            # Verify data integrity
            recovered = output.read_bytes()
            assert recovered == setup["plaintext"], f"Data mismatch for channel {ch}"


class TestReceiverStatsViaCliRunner:
    """Test stats integration through the CLI receive command."""

    def test_cli_receive_creates_session(self, setup: dict) -> None:
        pcap = _create_stego_pcap(setup, "icmp")
        output = str(setup["tmp_path"] / "recovered_cli.txt")
        runner = CliRunner()

        result = runner.invoke(cli, [
            "receive",
            "--channel", "icmp",
            "--sender-ip", "10.0.0.1",
            "--key-file", str(setup["key_path"]),
            "--output", output,
            "--pcap-in", pcap,
        ])
        assert result.exit_code == 0, f"CLI output: {result.output}"
        assert "session:" in result.output
        assert Path(output).exists()
