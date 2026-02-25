import socket
from unittest.mock import MagicMock, patch

import pytest
import yaml

from ddos_martummai.init_models import AppConfig, MitigationConfig, SystemConfig
from ddos_martummai.setup_wizard import SetupWizard


@pytest.fixture
def mock_app_config():
    return AppConfig(system=SystemConfig(), mitigation=MitigationConfig())


@pytest.fixture
def wizard(tmp_path, mock_app_config):
    config_path = tmp_path / "config.yml"
    return SetupWizard(config_path, mock_app_config)


def test_get_network_interfaces_success(wizard):
    snic = MagicMock()
    snic.family = socket.AF_INET
    snic.address = "192.168.1.50"

    mock_addrs = {
        "eth0": [snic],
        "lo": [],
    }

    with patch("psutil.net_if_addrs", return_value=mock_addrs):
        choices = wizard._get_network_interfaces()

        assert len(choices) == 2
        # Check that the first choice corresponds to eth0 with the correct IP
        assert "eth0" in choices[0].title
        assert "192.168.1.50" in choices[0].title
        assert choices[0].value == "eth0"


def test_get_network_interfaces_handles_exception(wizard):
    with patch("psutil.net_if_addrs", side_effect=Exception("Permission denied")):
        choices = wizard._get_network_interfaces()
        assert choices == []


def test_setup_interface_select_from_list(wizard):
    with patch.object(wizard, "_get_network_interfaces") as mock_get_iface:
        mock_get_iface.return_value = ["Choice1"]

        # Mock questionary.select
        with patch("questionary.select") as mock_select:
            # Simulate user selecting "Choice1"
            mock_select.return_value.ask.return_value = "eth0"

            wizard._setup_interface()

            mock_select.assert_called_once()
            assert wizard.app_config.system.interface == "eth0"


def test_setup_interface_manual_entry_when_empty(wizard):
    with patch.object(wizard, "_get_network_interfaces", return_value=[]):
        # Mock questionary.text
        with patch("questionary.text") as mock_text:
            # Simulate user typing 'wlan0'
            mock_text.return_value.ask.return_value = "wlan0"

            wizard._setup_interface()

            mock_text.assert_called_once()
            assert wizard.app_config.system.interface == "wlan0"


def test_setup_interface_cancelled_raises_interrupt(wizard):
    with patch.object(wizard, "_get_network_interfaces", return_value=["eth0"]):
        with patch("questionary.select") as mock_select:
            # Simulate user cancelling the selection (returns None)
            mock_select.return_value.ask.return_value = None

            with pytest.raises(KeyboardInterrupt):
                wizard._setup_interface()


def test_setup_interface_loops_on_empty_selection(wizard):
    with (
        patch.object(wizard, "_get_network_interfaces", return_value=["eth0"]),
        patch("questionary.select") as mock_select,
        patch("ddos_martummai.setup_wizard.console.print") as mock_print,
    ):
        # 2. Key Point: User first selects "" (empty) which should trigger the error message and loop again, then selects "eth0"
        mock_select.return_value.ask.side_effect = ["", "eth0"]

        wizard._setup_interface()

        # 3. Call Questionary select twice due to the loop
        assert mock_select.return_value.ask.call_count == 2

        print_calls = [args[0] for args, _ in mock_print.call_args_list]
        assert any("Interface is required" in str(msg) for msg in print_calls)
        assert wizard.app_config.system.interface == "eth0"


def test_setup_email_enabled(wizard):
    with (
        patch("questionary.confirm") as mock_confirm,
        patch("questionary.text") as mock_text,
        patch("questionary.password") as mock_pass,
    ):
        # 1. Confirm: Yes
        mock_confirm.return_value.ask.return_value = True

        # 2. Text inputs: AdminEmail, SmtpUser, SmtpServer, SmtpPort
        mock_text.return_value.ask.side_effect = [
            "admin@test.com",  # Admin Email
            "sender@test.com",  # SMTP User
            "smtp.gmail.com",  # SMTP Server
            "587",  # SMTP Port
        ]

        # 3. Password input
        mock_pass.return_value.ask.return_value = "secret123"

        wizard._setup_email()

        conf = wizard.app_config.mitigation
        assert conf.admin_email == "admin@test.com"
        assert conf.smtp_user == "sender@test.com"
        assert conf.smtp_password == "secret123"
        assert conf.smtp_port == 587


def test_setup_email_disabled(wizard):
    with (
        patch("questionary.confirm") as mock_confirm,
        patch("questionary.text") as mock_text,
    ):
        mock_confirm.return_value.ask.return_value = False

        wizard._setup_email()

        mock_text.assert_not_called()
        assert wizard.app_config.mitigation.admin_email == ""


def test_email_validation_logic_function(wizard):
    with (
        patch("questionary.confirm") as mock_confirm,
        patch("questionary.text") as mock_text,
        patch("questionary.password") as mock_pass,
    ):
        # Setup
        mock_confirm.return_value.ask.return_value = True
        mock_text.return_value.ask.side_effect = [
            "admin@test.com",  # Admin Email
            "sender@test.com",  # SMTP User
            "smtp.gmail.com",  # SMTP Server
            "587",  # SMTP Port
        ]
        mock_pass.return_value.ask.return_value = "secret"

        wizard._setup_email()

        # Key Point: get the validator function
        _, kwargs = mock_text.call_args_list[0]
        validator_func = kwargs["validate"]

        # Case Fail
        msg_warning = "This field is required!"
        assert validator_func("") == msg_warning
        assert validator_func("   ") == msg_warning

        # Case Success
        assert validator_func("admin@test.com") is True


def test_setup_blocking_enabled(wizard):
    with (
        patch("questionary.confirm") as mock_confirm,
        patch("questionary.text") as mock_text,
    ):
        mock_confirm.return_value.ask.return_value = True
        mock_text.return_value.ask.return_value = "300"

        wizard._setup_blocking()

        assert wizard.app_config.mitigation.enable_blocking is True
        assert wizard.app_config.mitigation.block_duration_seconds == 300


def test_setup_blocking_disabled(wizard):
    with patch("questionary.confirm") as mock_confirm:
        mock_confirm.return_value.ask.return_value = False

        wizard._setup_blocking()

        assert wizard.app_config.mitigation.enable_blocking is False


def test_save_config_success(wizard):
    # Mock config changes
    wizard.app_config.system.interface = "eth99"

    success = wizard._save_config()

    assert success is True
    assert wizard.config_path.exists()

    # Read back the file to verify contents
    with open(wizard.config_path) as f:
        data = yaml.safe_load(f)
        assert data["system"]["interface"] == "eth99"


def test_save_config_permission_error(wizard):
    mock_path = MagicMock()
    mock_path.open.side_effect = PermissionError("Access Denied")
    mock_path.parent.mkdir.return_value = None
    wizard.config_path = mock_path

    success = wizard._save_config()

    assert success is False
    mock_path.open.assert_called_once()


def test_save_config_generic_error(wizard):
    mock_path = MagicMock()
    mock_path.open.side_effect = OSError("Disk full")
    mock_path.parent.mkdir.return_value = None

    wizard.config_path = mock_path

    success = wizard._save_config()

    assert success is False
    mock_path.open.assert_called_once()


# Integration Test


def test_run_full_success_flow(wizard):
    with (
        patch.object(wizard, "_setup_interface") as mock_setup_iface,
        patch.object(wizard, "_setup_email") as mock_setup_email,
        patch.object(wizard, "_setup_blocking") as mock_setup_block,
        patch.object(wizard, "_save_config", return_value=True) as mock_save,
    ):
        result = wizard.run()

        assert result is True
        mock_setup_iface.assert_called_once()
        mock_setup_email.assert_called_once()
        mock_setup_block.assert_called_once()
        mock_save.assert_called_once()


def test_run_keyboard_interrupt_returns_false(wizard):
    with patch.object(wizard, "_setup_interface", side_effect=KeyboardInterrupt):
        result = wizard.run()

        assert result is False
