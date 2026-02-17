from unittest.mock import MagicMock, patch

from ddos_martummai.mitigation import Mitigator


def test_valid_ip_local_interface_returns_false(mock_app_config):
    mitigator = Mitigator(mock_app_config)
    with patch("psutil.net_if_addrs") as mock_net:
        addr = MagicMock()
        addr.address = "192.168.1.50"
        mock_net.return_value = {"eth0": [addr]}

        assert mitigator._valid_ip("192.168.1.50") is False


def test_block_ip_valid_ip_calls_iptables(mock_app_config):
    mitigator = Mitigator(mock_app_config)
    with (
        patch("subprocess.run") as mock_run,
        patch.object(mitigator, "_valid_ip", return_value=True),
    ):
        # Simulate check fail (rule doesn't exist)
        mock_run.side_effect = [MagicMock(returncode=1), MagicMock(returncode=0)]

        mitigator.block_ip("10.0.0.1")

        args_list = mock_run.call_args_list
        assert args_list[1][0][0][1] == "-A"  # Ensure add rule flag


def test_send_alert_smtp_enabled_sends_email(mock_app_config):
    mitigator = Mitigator(mock_app_config)
    with patch("smtplib.SMTP") as mock_smtp:
        mitigator.send_alert("1.2.3.4", "flow info")
        mock_smtp.return_value.__enter__.return_value.send_message.assert_called()


def test_send_alert_missing_config_returns_early(mock_app_config):
    mock_app_config.mitigation.admin_email = ""
    mitigator = Mitigator(mock_app_config)
    with patch("smtplib.SMTP") as mock_smtp:
        mitigator.send_alert("1.2.3.4", "flow info")
        mock_smtp.assert_not_called()
