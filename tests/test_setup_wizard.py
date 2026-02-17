from unittest.mock import patch

from ddos_martummai.setup_wizard import SetupWizard


def test_setup_interface_user_selects_updates_config(mock_app_config, tmp_path):
    wizard = SetupWizard(tmp_path / "config.yml", mock_app_config)

    with patch("questionary.select") as mock_select:
        mock_select.return_value.ask.return_value = "eth0"
        with patch(
            "ddos_martummai.setup_wizard.SetupWizard._get_network_interfaces",
            return_value=["eth0"],
        ):
            wizard._setup_interface()
            assert wizard.app_config.system.interface == "eth0"


def test_setup_email_enabled_updates_config(mock_app_config, tmp_path):
    wizard = SetupWizard(tmp_path / "config.yml", mock_app_config)

    with (
        patch("questionary.confirm") as mock_confirm,
        patch("questionary.text") as mock_text,
        patch("questionary.password") as mock_pass,
    ):
        mock_confirm.return_value.ask.return_value = True
        mock_text.return_value.ask.side_effect = [
            "admin@test.com",
            "sender@test.com",
            "smtp.test.com",
            "587",
        ]
        mock_pass.return_value.ask.return_value = "secret"

        wizard._setup_email()
        assert wizard.app_config.mitigation.admin_email == "admin@test.com"


def test_save_config_permission_error_returns_false(mock_app_config, tmp_path):
    protected_file = tmp_path / "protected.yml"
    wizard = SetupWizard(protected_file, mock_app_config)

    with patch("builtins.open", side_effect=PermissionError):
        success = wizard._save_config()
        assert success is False
