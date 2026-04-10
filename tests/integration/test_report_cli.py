"""Integration tests for the CLI report command."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from netstego.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestReportCommand:
    def test_report_skip_monitoring(self, runner: CliRunner, tmp_path: Path) -> None:
        out_dir = str(tmp_path / "results")
        result = runner.invoke(cli, [
            "report",
            "--output-dir", out_dir,
            "--skip-monitoring",
            "--repeat", "1",
            "--payload-sizes", "64",
        ])
        assert result.exit_code == 0, f"OUTPUT:\n{result.output}"
        assert "Running pipeline benchmarks" in result.output
        assert "Generating charts" in result.output
        assert "Done!" in result.output

        # Check data files
        data_dir = Path(out_dir) / "data"
        assert (data_dir / "benchmark_results.json").exists()
        bench_data = json.loads((data_dir / "benchmark_results.json").read_text())
        assert "pipeline_benchmarks" in bench_data
        assert len(bench_data["pipeline_benchmarks"]) == 5  # 5 channels x 1 size

        # Check charts
        charts_dir = Path(out_dir) / "charts"
        assert charts_dir.exists()
        pngs = list(charts_dir.glob("*.png"))
        assert len(pngs) >= 4  # at least throughput, timing, packets_vs_payload, throughput_by_payload

    def test_report_benchmark_summary_table(self, runner: CliRunner, tmp_path: Path) -> None:
        out_dir = str(tmp_path / "results")
        result = runner.invoke(cli, [
            "report",
            "--output-dir", out_dir,
            "--skip-monitoring",
            "--repeat", "1",
            "--payload-sizes", "1024",
        ])
        assert result.exit_code == 0
        # Summary table should mention channels
        assert "icmp" in result.output
        assert "ip-id" in result.output

    def test_report_with_monitoring(self, runner: CliRunner, tmp_path: Path) -> None:
        """Full report including detection monitoring (single channel, minimal trials)."""
        out_dir = str(tmp_path / "results")
        result = runner.invoke(cli, [
            "report",
            "--output-dir", out_dir,
            "--repeat", "1",
            "--payload-sizes", "64",
        ])
        assert result.exit_code == 0, f"OUTPUT:\n{result.output}"
        assert "Running detection monitoring" in result.output

        # Monitoring data should be saved
        data_dir = Path(out_dir) / "data"
        assert (data_dir / "monitoring_results.json").exists()
        mon_data = json.loads((data_dir / "monitoring_results.json").read_text())
        assert "metrics" in mon_data

        # Detection accuracy chart should exist
        charts_dir = Path(out_dir) / "charts"
        assert (charts_dir / "detection_accuracy.png").exists()

    def test_report_multiple_payload_sizes(self, runner: CliRunner, tmp_path: Path) -> None:
        out_dir = str(tmp_path / "results")
        result = runner.invoke(cli, [
            "report",
            "--output-dir", out_dir,
            "--skip-monitoring",
            "--repeat", "1",
            "--payload-sizes", "64,256",
        ])
        assert result.exit_code == 0
        bench_data = json.loads((Path(out_dir) / "data" / "benchmark_results.json").read_text())
        # 5 channels x 2 sizes = 10
        assert len(bench_data["pipeline_benchmarks"]) == 10

    def test_report_creates_nested_dirs(self, runner: CliRunner, tmp_path: Path) -> None:
        out_dir = str(tmp_path / "deep" / "nested" / "results")
        result = runner.invoke(cli, [
            "report",
            "--output-dir", out_dir,
            "--skip-monitoring",
            "--repeat", "1",
            "--payload-sizes", "64",
        ])
        assert result.exit_code == 0
        assert Path(out_dir, "data", "benchmark_results.json").exists()
        assert Path(out_dir, "charts").exists()
