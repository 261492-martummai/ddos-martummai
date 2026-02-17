from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ddos_martummai.main import main


@pytest.fixture
def runner():
    return CliRunner()


def test_main_help(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "DDoS Martummai Guard" in result.output


def test_main_root_check_fail(runner):
    with patch("ddos_martummai.main.is_root_privileged", return_value=False):
        result = runner.invoke(main, ["--verbose"])
        assert result.exit_code == 1
        assert "requires root privileges" in result.output


def test_main_setup_mode(runner, tmp_path):
    with (
        patch("ddos_martummai.main.is_root_privileged", return_value=True),
        patch("ddos_martummai.main.SetupWizard") as mock_wizard,
    ):
        mock_wizard.return_value.run.return_value = True
        result = runner.invoke(main, ["--setup", "-c", str(tmp_path / "config.yml")])

        assert result.exit_code == 0
        mock_wizard.return_value.run.assert_called_once()


def test_main_test_mode_integration(runner, tmp_path, mock_app_config):
    # Create Dummy PCAP
    pcap_file = tmp_path / "test.pcap"
    pcap_file.touch()

    # Mock Components
    with (
        patch("ddos_martummai.main.DDoSConfigLoader") as mock_loader,
        patch("ddos_martummai.main.Reader") as mock_reader,
        patch("ddos_martummai.main.DDoSPreprocessor") as mock_prep,
        patch("ddos_martummai.main.DDoSDetector") as mock_det,
        patch("threading.Thread") as mock_thread,
    ):
        # Setup Config Loader Return
        mock_loader.return_value.app_config = mock_app_config

        # Setup Thread mocks
        t_reader = MagicMock()
        t_reader.is_alive.return_value = True
        t_prep = MagicMock()
        t_prep.is_alive.return_value = True
        t_det = MagicMock()
        t_det.is_alive.side_effect = [
            True,
            False,
        ]

        mock_thread.side_effect = [t_reader, t_prep, t_det]
        result = runner.invoke(main, ["-t", "-f", str(pcap_file)])

        # Assertions
        assert result.exit_code == 0
        mock_reader.assert_called()
        mock_prep.assert_called()
        mock_det.assert_called()
        t_reader.start.assert_called()
