"""Integration tests for CLI commands via Click's CliRunner.

Tests CLI without requiring network or admin privileges.
"""

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from netstego.cli import cli
from netstego.core.crypto import generate_key


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def setup_files(tmp_path: Path) -> dict:
    """Create test key and file for CLI tests."""
    key_path = tmp_path / "test.key"
    generate_key(key_path)

    file_path = tmp_path / "secret.txt"
    file_path.write_text("This is a secret message for CLI testing!")

    pcap_path = tmp_path / "output.pcap"

    return {
        "key_path": str(key_path),
        "file_path": str(file_path),
        "pcap_path": str(pcap_path),
        "tmp_path": tmp_path,
    }


class TestKeygenCommand:
    def test_keygen_creates_file(self, runner: CliRunner, tmp_path: Path) -> None:
        key_out = str(tmp_path / "new.key")
        result = runner.invoke(cli, ["keygen", "--output", key_out])
        assert result.exit_code == 0
        assert Path(key_out).exists()
        assert len(Path(key_out).read_bytes()) == 32
        assert "Key generated" in result.output


class TestBenchmarkCommand:
    def test_benchmark_icmp(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, [
            "benchmark", "--channel", "icmp", "--dest", "127.0.0.1", "--duration", "1"
        ])
        assert result.exit_code == 0
        assert "Packets created" in result.output
        assert "Rate" in result.output

    def test_benchmark_ip_id(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, [
            "benchmark", "--channel", "ip-id", "--dest", "127.0.0.1", "--duration", "1"
        ])
        assert result.exit_code == 0
        assert "Packets created" in result.output


class TestReceiveFromPcap:
    """Test receive command reading from PCAP (no network needed)."""

    def _create_stego_pcap(self, setup: dict, channel_name: str) -> str:
        """Helper: create a PCAP with steganographic data."""
        from netstego.core.crypto import encrypt, load_key
        from netstego.core.fragmentation import fragment
        from netstego.network.sender import frame_chunks, get_channel
        from scapy.utils import wrpcap

        key = load_key(Path(setup["key_path"]))
        plaintext = Path(setup["file_path"]).read_bytes()
        ciphertext = encrypt(plaintext, key)

        channel = get_channel(channel_name)
        bytes_per_packet = channel.bits_per_packet // 8
        overhead = 17 + 4
        chunk_data_size = (bytes_per_packet - overhead) if bytes_per_packet > overhead + 33 else 128
        chunks = fragment(ciphertext, chunk_data_size)
        framed = frame_chunks(chunks)
        packets = channel.encode(framed, dest_ip="10.0.0.2")

        pcap_path = setup["pcap_path"]
        wrpcap(pcap_path, packets)
        return pcap_path

    def test_receive_icmp_from_pcap(self, runner: CliRunner, setup_files: dict) -> None:
        pcap = self._create_stego_pcap(setup_files, "icmp")
        output = str(setup_files["tmp_path"] / "recovered.txt")

        result = runner.invoke(cli, [
            "receive",
            "--channel", "icmp",
            "--sender-ip", "10.0.0.1",
            "--key-file", setup_files["key_path"],
            "--output", output,
            "--pcap-in", pcap,
        ])
        assert result.exit_code == 0, f"OUT: {result.output}"
        assert Path(output).exists()

        original = Path(setup_files["file_path"]).read_bytes()
        recovered = Path(output).read_bytes()
        assert recovered == original

    def test_receive_ip_id_from_pcap(self, runner: CliRunner, setup_files: dict) -> None:
        pcap = self._create_stego_pcap(setup_files, "ip-id")
        output = str(setup_files["tmp_path"] / "recovered.txt")

        result = runner.invoke(cli, [
            "receive",
            "--channel", "ip-id",
            "--sender-ip", "10.0.0.1",
            "--key-file", setup_files["key_path"],
            "--output", output,
            "--pcap-in", pcap,
        ])
        assert result.exit_code == 0, f"OUT: {result.output}"
        recovered = Path(output).read_bytes()
        original = Path(setup_files["file_path"]).read_bytes()
        assert recovered == original

    def test_receive_tcp_isn_from_pcap(self, runner: CliRunner, setup_files: dict) -> None:
        pcap = self._create_stego_pcap(setup_files, "tcp-isn")
        output = str(setup_files["tmp_path"] / "recovered.txt")

        result = runner.invoke(cli, [
            "receive",
            "--channel", "tcp-isn",
            "--sender-ip", "10.0.0.1",
            "--key-file", setup_files["key_path"],
            "--output", output,
            "--pcap-in", pcap,
        ])
        assert result.exit_code == 0, f"OUT: {result.output}"
        recovered = Path(output).read_bytes()
        original = Path(setup_files["file_path"]).read_bytes()
        assert recovered == original

    def test_receive_dns_from_pcap(self, runner: CliRunner, setup_files: dict) -> None:
        pcap = self._create_stego_pcap(setup_files, "dns")
        output = str(setup_files["tmp_path"] / "recovered.txt")

        result = runner.invoke(cli, [
            "receive",
            "--channel", "dns",
            "--sender-ip", "10.0.0.1",
            "--key-file", setup_files["key_path"],
            "--output", output,
            "--pcap-in", pcap,
        ])
        assert result.exit_code == 0, f"OUT: {result.output}"
        recovered = Path(output).read_bytes()
        original = Path(setup_files["file_path"]).read_bytes()
        assert recovered == original

    def test_receive_tcp_ts_from_pcap(self, runner: CliRunner, setup_files: dict) -> None:
        pcap = self._create_stego_pcap(setup_files, "tcp-ts")
        output = str(setup_files["tmp_path"] / "recovered.txt")

        result = runner.invoke(cli, [
            "receive",
            "--channel", "tcp-ts",
            "--sender-ip", "10.0.0.1",
            "--key-file", setup_files["key_path"],
            "--output", output,
            "--pcap-in", pcap,
        ])
        assert result.exit_code == 0, f"OUT: {result.output}"
        recovered = Path(output).read_bytes()
        original = Path(setup_files["file_path"]).read_bytes()
        assert recovered == original


class TestDetectCommand:
    def test_detect_on_stego_pcap(self, runner: CliRunner, setup_files: dict) -> None:
        """Create stego PCAP and run detect."""
        from netstego.channels.icmp_payload import IcmpPayloadChannel
        from scapy.utils import wrpcap

        channel = IcmpPayloadChannel()
        data = os.urandom(2000)
        packets = channel.encode(data, dest_ip="10.0.0.2")
        pcap = str(setup_files["tmp_path"] / "stego.pcap")
        wrpcap(pcap, packets)

        report_path = str(setup_files["tmp_path"] / "report.json")
        result = runner.invoke(cli, [
            "detect",
            "--input", pcap,
            "--methods", "statistical,signatures",
            "--report", report_path,
        ])
        assert result.exit_code == 0
        assert Path(report_path).exists()
        assert "Detection Report" in result.output


class TestStatsCommand:
    def test_stats_empty(self, runner: CliRunner, tmp_path: Path) -> None:
        db_path = str(tmp_path / "stats.db")
        result = runner.invoke(cli, ["stats", "--db", db_path])
        assert result.exit_code == 0
        assert "No sessions found" in result.output
